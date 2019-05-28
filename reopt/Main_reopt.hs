{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeOperators #-}
module Main (main) where

import           Control.Exception
import           Control.Lens
import           Control.Monad
import           Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import           Data.ElfEdit
import           Data.List ((\\), nub, stripPrefix, intercalate)
import           Data.Parameterized.Some
import           Data.Version
import           Data.Word
import qualified Data.Yaml as Yaml
import           GHC.Stack
import           Numeric
import           System.Console.CmdArgs.Explicit
import           System.Environment (getArgs)
import           System.Exit (exitFailure)
import           System.FilePath
import           System.IO
import           System.IO.Error
import           System.Posix.Files
import           Text.PrettyPrint.ANSI.Leijen hiding ((<$>), (</>), (<>))

import           Data.Macaw.DebugLogging
import           Data.Macaw.Discovery
import           Data.Macaw.Memory.LoadCommon

import           Reopt
import qualified Reopt.CFG.LLVM as LLVM
import qualified Reopt.CFG.LLVM.X86 as LLVM
import           Reopt.Interface
import           Reopt.Relinker

import           Paths_reopt (version)

------------------------------------------------------------------------
-- Utilities

unintercalate :: String -> String -> [String]
unintercalate punct str = reverse $ go [] "" str
  where
    go acc "" [] = acc
    go acc thisAcc [] = (reverse thisAcc) : acc
    go acc thisAcc str'@(x : xs)
      | Just sfx <- stripPrefix punct str' = go ((reverse thisAcc) : acc) "" sfx
      | otherwise = go acc (x : thisAcc) xs

-- | We'll use stderr to log error messages
logger :: String -> IO ()
logger = hPutStrLn stderr

------------------------------------------------------------------------
-- Action

-- | Action to perform when running
data Action
   = DumpDisassembly -- ^ Print out disassembler output only.
   | ShowCFG         -- ^ Print out control-flow microcode.
   | ShowFunctions   -- ^ Print out generated functions
   | ShowHelp        -- ^ Print out help message
   | ShowVersion     -- ^ Print out version
   | Relink          -- ^ Link an existing binary and new code together.
   | Reopt           -- ^ Perform a full reoptimization
  deriving (Show)

------------------------------------------------------------------------
-- Args

-- | Command line arguments.
data Args
   = Args { _reoptAction  :: !Action
          , _programPath  :: !FilePath
            -- ^ Path to input program to optimize/export
          , _debugKeys    :: [DebugClass]
            -- Debug information ^ TODO: See if we can omit this.

          , _newobjPath   :: !FilePath
            -- ^ Path for new object to merge into program
            --
            -- Only used when reoptAction is @Relink@.
          , _redirPath    :: !FilePath
            -- ^ Path to file for manual redirections.
            --
            -- Only used when reoptAction is @Relink@.
          , _outputPath   :: !FilePath
            -- ^ Path to output
            --
            -- Only used when reoptAction is @Relink@ and @Reopt@.

          , _llvmVersion  :: !LLVMConfig
            -- ^ LLVM version to generate LLVM for.
            --
            -- Only used when generating LLVM.
          , _optPath      :: !FilePath
            -- ^ Path to LLVM opt command.
            --
            -- Only used when generating LLVM to be optimized.
          , _llcPath      :: !FilePath
            -- ^ Path to LLVM `llc` command
            --
            -- Only used when generating assembly file.
          , _optLevel     :: !Int
            -- ^ Optimization level to pass to opt and llc
            --
            -- This defaults to 2
          , _llvmMcPath      :: !FilePath
            -- ^ Path to llvm-mc
            --
            -- Only used when generating object file from assembly generated by llc.
          , _includeAddrs   :: ![String]
            -- ^ List of entry points for translation
          , _excludeAddrs :: ![String]
            -- ^ List of function entry points that we exclude for translation.
          , _loadOpts :: !LoadOptions
            -- ^ Options affecting initial memory construction
          , _discOpts :: !DiscoveryOptions
            -- ^ Options affecting discovery
          }

-- | Action to perform when running
reoptAction :: Simple Lens Args Action
reoptAction = lens _reoptAction (\s v -> s { _reoptAction = v })

-- | Path for main executable
programPath :: Simple Lens Args FilePath
programPath = lens _programPath (\s v -> s { _programPath = v })

-- | Which debug keys (if any) to output
debugKeys :: Simple Lens Args [DebugClass]
debugKeys = lens _debugKeys (\s v -> s { _debugKeys = v })

-- | Path to new object code for relinker
newobjPath :: Simple Lens Args FilePath
newobjPath = lens _newobjPath (\s v -> s { _newobjPath = v })

-- | Path to JSON file describing the redirections
redirPath :: Simple Lens Args FilePath
redirPath = lens _redirPath (\s v -> s { _redirPath = v })

-- | Path to JSON file describing the output
outputPath :: Simple Lens Args FilePath
outputPath = lens _outputPath (\s v -> s { _outputPath = v })

-- | Path to llvm-mc
llvmMcPath :: Simple Lens Args FilePath
llvmMcPath = lens _llvmMcPath (\s v -> s { _llvmMcPath = v })

-- | Version to use when printing LLVM.
llvmVersion :: Simple Lens Args LLVMConfig
llvmVersion = lens _llvmVersion (\s v -> s { _llvmVersion = v })

-- | Path to llc
llcPath :: Simple Lens Args FilePath
llcPath = lens _llcPath (\s v -> s { _llcPath = v })

-- | Path to opt
optPath :: Simple Lens Args FilePath
optPath = lens _optPath (\s v -> s { _optPath = v })

-- | Optimization level to pass to llc and opt
optLevel :: Simple Lens Args Int
optLevel = lens _optLevel (\s v -> s { _optLevel = v })

-- | Function entry points to translate (overrides notrans if non-empty)
includeAddrs :: Simple Lens Args [String]
includeAddrs = lens _includeAddrs (\s v -> s { _includeAddrs = v })

-- | Function entry points that we exclude for translation.
excludeAddrs :: Simple Lens Args [String]
excludeAddrs = lens _excludeAddrs (\s v -> s { _excludeAddrs = v })

-- | Options for controlling loading binaries to memory.
loadOpts :: Simple Lens Args LoadOptions
loadOpts = lens _loadOpts (\s v -> s { _loadOpts = v })

-- | Options for controlling discovery
discOpts :: Simple Lens Args DiscoveryOptions
discOpts = lens _discOpts (\s v -> s { _discOpts = v })

-- | Initial arguments if nothing is specified.
defaultArgs :: Args
defaultArgs = Args { _reoptAction = Reopt
                   , _programPath = ""
                   , _debugKeys = []
                   , _newobjPath = ""
                   , _redirPath  = ""
                   , _outputPath = "a.out"
                   , _llvmVersion = latestLLVMConfig
                   , _optPath = "opt"
                   , _optLevel  = 2
                   , _llcPath = "llc"
                   , _llvmMcPath = "llvm-mc"
                   , _includeAddrs = []
                   , _excludeAddrs  = []
                   , _loadOpts     = defaultLoadOptions
                   , _discOpts     = defaultDiscoveryOptions
                   }

-- | Discovery symbols in program and show function CFGs.
showCFG :: Args -> IO String
showCFG args = do
  Some disc_info <-
    discoverBinary (args^.programPath) (args^.loadOpts) (args^.discOpts) (args^.includeAddrs) (args^.excludeAddrs)
  pure $ show $ ppDiscoveryStateBlocks disc_info

showFunctions :: Args -> IO ()
showFunctions args = do
  (os, s, _) <-
    discoverX86Binary (args^.programPath) (args^.loadOpts) (args^.discOpts) (args^.includeAddrs) (args^.excludeAddrs)
  fns <- getFns logger (osPersonality os) s
  mapM_ (print . pretty) fns

------------------------------------------------------------------------
-- Loading flags

resolveHex :: String -> Maybe Integer
resolveHex ('0':'x':wval) | [(w,"")] <- readHex wval = Just w
resolveHex ('0':'X':wval) | [(w,"")] <- readHex wval = Just w
resolveHex _ = Nothing

-- | Define a flag that forces the region index to 0 and adjusts
-- the base pointer address.
--
-- Primarily used for loading shared libraries at a fixed address.
loadForceAbsoluteFlag :: Flag Args
loadForceAbsoluteFlag = flagReq [ "force-absolute" ] upd "OFFSET" help
  where help = "Load a relocatable file at a fixed offset."
        upd :: String -> Args -> Either String Args
        upd val args =
          case resolveHex val of
            Just off -> Right $
               args & loadOpts %~ \opt -> opt { loadRegionIndex = Just 0
                                              , loadRegionBaseOffset = off
                                              }
            Nothing -> Left $
              "Expected a hexadecimal address of form '0x???', passsed "
              ++ show val

------------------------------------------------------------------------
-- Other Flags

disassembleFlag :: Flag Args
disassembleFlag = flagNone [ "disassemble", "d" ] upd help
  where upd  = reoptAction .~ DumpDisassembly
        help = "Disassemble code segment of binary, and print it in an objdump style."

cfgFlag :: Flag Args
cfgFlag = flagNone [ "cfg", "c" ] upd help
  where upd  = reoptAction .~ ShowCFG
        help = "Print out the functions recovered from an executable."

llvmVersionFlag :: Flag Args
llvmVersionFlag = flagReq [ "llvm-version" ] upd "VERSION" help
  where upd :: String -> Args -> Either String Args
        upd s old = do
          v <- case versionOfString s of
                 Just v -> Right v
                 Nothing -> Left $ "Could not interpret LLVM version."
          cfg <- case getLLVMConfig v of
                   Just c -> pure c
                   Nothing -> Left $ "Unsupported LLVM version " ++ show s ++ "."
          pure $ old & llvmVersion .~ cfg

        help = "LLVM version (e.g. 3.5.2)"

funFlag :: Flag Args
funFlag = flagNone [ "functions", "f" ] upd help
  where upd  = reoptAction .~ ShowFunctions
        help = "Print out functions after stack and argument recovery."

parseDebugFlags ::  [DebugClass] -> String -> Either String [DebugClass]
parseDebugFlags oldKeys cl =
  case cl of
    '-' : cl' -> do ks <- getKeys cl'
                    return (oldKeys \\ ks)
    cl'       -> do ks <- getKeys cl'
                    return (nub $ oldKeys ++ ks)
  where
    getKeys "all" = Right allDebugKeys
    getKeys str = case parseDebugKey str of
                    Nothing -> Left $ "Unknown debug key `" ++ str ++ "'"
                    Just k  -> Right [k]

debugFlag :: Flag Args
debugFlag = flagOpt "all" [ "debug", "D" ] upd "FLAGS" help
  where upd s old = do let ks = unintercalate "," s
                       new <- foldM parseDebugFlags (old ^. debugKeys) ks
                       Right $ (debugKeys .~ new) old
        help = "Debug keys to enable.  This flag may be used multiple times, "
            ++ "with comma-separated keys.  Keys may be preceded by a '-' which "
            ++ "means disable that key.\n"
            ++ "Supported keys: all, " ++ intercalate ", " (map debugKeyName allDebugKeys)

outputFlag :: Flag Args
outputFlag = flagReq [ "o", "output" ] upd "PATH" help
  where upd s old = Right $ old & outputPath .~ s
        help = "Path to write new binary."

-- | Flag to set path to opt.
optPathFlag :: Flag Args
optPathFlag = flagReq [ "opt" ] upd "PATH" help
  where upd s old = Right $ old & optPath .~ s
        help = "Path to LLVM \"opt\" command for optimization."

-- | Flag to set llc path.
llcPathFlag :: Flag Args
llcPathFlag = flagReq [ "llc" ] upd "PATH" help
  where upd s old = Right $ old & llcPath .~ s
        help = "Path to LLVM \"llc\" command for compiling LLVM to native assembly."

-- | Flag to set path to llvm-mc
llvmMcPathFlag :: Flag Args
llvmMcPathFlag = flagReq [ "llvm-mc" ] upd "PATH" help
  where upd s old = Right $ old & llvmMcPath .~ s
        help = "Path to llvm-mc"

-- | Flag to set llc optimization level.
optLevelFlag :: Flag Args
optLevelFlag = flagReq [ "O", "opt-level" ] upd "PATH" help
  where upd s old =
          case reads s of
            [(lvl, "")] | 0 <= lvl && lvl <= 3 -> Right $ old & optLevel .~ lvl
            _ -> Left "Expected optimization level to be a number between 0 and 3."
        help = "Optimization level."

-- | Used to add a new function to ignore translation of.
includeAddrFlag :: Flag Args
includeAddrFlag = flagReq [ "include" ] upd "ADDR" help
  where upd s old = Right $ old & includeAddrs %~ (s:)
        help = "Address of function to include in analysis (may be repeated)."

-- | Used to add a new function to ignore translation of.
excludeAddrFlag :: Flag Args
excludeAddrFlag = flagReq [ "exclude" ] upd "ADDR" help
  where upd s old = Right $ old & excludeAddrs %~ (s:)
        help = "Address of function to exclude in analysis (may be repeated)."

-- | Print out a trace message when we analyze a function
logAtAnalyzeFunctionFlag :: Flag Args
logAtAnalyzeFunctionFlag = flagBool [ "trace-function-discovery" ] upd help
  where upd b = discOpts %~ \o -> o { logAtAnalyzeFunction = b }
        help = "Report when starting analysis of each function."

-- | Print out a trace message when we analyze a function
logAtAnalyzeBlockFlag :: Flag Args
logAtAnalyzeBlockFlag = flagBool [ "trace-block-discovery" ] upd help
  where upd b = discOpts %~ \o -> o { logAtAnalyzeBlock = b }
        help = "Report when starting analysis of each basic block with a function."

exploreFunctionSymbolsFlag :: Flag Args
exploreFunctionSymbolsFlag = flagBool [ "include-syms" ] upd help
  where upd b = discOpts %~ \o -> o { exploreFunctionSymbols = b }
        help = "Include function symbols in discovery."

exploreCodeAddrInMemFlag :: Flag Args
exploreCodeAddrInMemFlag = flagBool [ "include-mem" ] upd help
  where upd b = discOpts %~ \o -> o { exploreCodeAddrInMem = b }
        help = "Include memory code addresses in discovery."

relinkFlag :: Flag Args
relinkFlag = flagNone [ "r", "relink" ] upd help
  where upd  = reoptAction .~ Relink
        help = "Only run relinker with existing object file, binary, and a patch file"

objectPathFlag :: Flag Args
objectPathFlag = flagReq [ "object" ] upd "PATH" help
  where upd s old = Right $ old & newobjPath .~ s
        help = "Path to new object code to link into existing binary."

patchFilePathFlag :: Flag Args
patchFilePathFlag = flagReq [ "patch-file" ] upd "PATH" help
  where upd s old = Right $ old & redirPath .~ s
        help = "Path to JSON file that specifies where to patch existing code."

arguments :: Mode Args
arguments = mode "reopt" defaultArgs help filenameArg flags
  where help = reoptVersion ++ "\n" ++ copyrightNotice
        flags = [ -- General purpose options
                  flagHelpSimple (reoptAction .~ ShowHelp)
                , flagVersion (reoptAction .~ ShowVersion)
                , debugFlag
                  -- Redirect output to file.
                , outputFlag
                  -- Discovery options
                , logAtAnalyzeFunctionFlag
                , logAtAnalyzeBlockFlag
                , exploreFunctionSymbolsFlag
                , exploreCodeAddrInMemFlag
                , includeAddrFlag
                , excludeAddrFlag
                  -- Loading options
                , loadForceAbsoluteFlag
                  -- LLVM options
                , llvmVersionFlag
                  -- Compilation options
                , optLevelFlag
                , optPathFlag
                , llcPathFlag
                , llvmMcPathFlag
                  -- Explicit Modes
                , disassembleFlag
                , cfgFlag
                , funFlag
                  -- Options for explicit relinking options
                , relinkFlag
                , objectPathFlag
                , patchFilePathFlag
                ]

reoptVersion :: String
reoptVersion = "Reopt binary reoptimizer (reopt) "  ++ versionString ++ "."
  where [h,l,r] = versionBranch version
        versionString = show h ++ "." ++ show l ++ "." ++ show r

copyrightNotice :: String
copyrightNotice = "Copyright 2014-19 Galois, Inc."

  -- | Flag to set the path to the binary to analyze.
filenameArg :: Arg Args
filenameArg = Arg { argValue = setFilename
                  , argType = "FILE"
                  , argRequire = False
                  }
  where setFilename :: String -> Args -> Either String Args
        setFilename nm a = Right (a & programPath .~ nm)

getCommandLineArgs :: IO Args
getCommandLineArgs = do
  argStrings <- getArgs
  case process arguments argStrings of
    Left msg -> do
      logger msg
      exitFailure
    Right v -> return v

-- | Merge a binary and new object
mergeAndWrite :: HasCallStack
              => FilePath
              -> Elf 64 -- ^ Original binary
              -> Elf 64 -- ^ New object
              -> [CodeRedirection Word64] -- ^ List of redirections from old binary to new.
              -> IO ()
mergeAndWrite output_path orig_binary new_obj redirs = do
  putStrLn $ "Performing final relinking."
  let mres = mergeObject orig_binary new_obj redirs x86_64_immediateJump
  case mres of
    Left e -> fail e
    Right new_binary -> do
      BSL.writeFile output_path $ renderElf new_binary
      -- Update the file mode
      do fs <- getFileStatus output_path
         let fm = ownerExecuteMode
               .|. groupExecuteMode
               .|. otherExecuteMode
         setFileMode output_path (fileMode fs `unionFileModes` fm)

-- | This is a mode for Reopt to just test that the relinker can successfully
-- combine two binaries.
performRelink :: Args -> IO ()
performRelink args = do
  -- Get original binary
  orig_binary <- readElf64 (args^.programPath)

  let output_path = args^.outputPath
  case args^.newobjPath of
    -- When no new object is provided, we just copy the input
    -- file to test out Elf decoder/encoder.
    "" -> do
      putStrLn $ "Copying binary to: " ++ output_path
      BSL.writeFile output_path $ renderElf orig_binary
    -- When a non-empty new obj is provided we test
    new_obj_path -> do
      putStrLn $ "new_obj_path: " ++ new_obj_path
      new_obj <- readElf64 new_obj_path
      redirs <-
        case args^.redirPath of
          "" -> return []
          redir_path -> do
            mredirs <- Yaml.decodeFileEither redir_path
            case mredirs of
              Left e -> fail $ show e
              Right r -> return r
      mergeAndWrite output_path orig_binary new_obj redirs

-- | Print out the disassembly of all executable sections.
--
-- Note.  This does not apply relocations.
dumpDisassembly :: FilePath -> IO ()
dumpDisassembly path = do
  bs <- checkedReadFile path
  e <- parseElf64 path bs
  let sections = filter isCodeSection $ e^..elfSections
  when (null sections) $ do
    hPutStrLn stderr "Binary contains no executable sections."
    exitFailure
  forM_ sections $ \s -> do
    printX86SectionDisassembly (elfSectionName s) (elfSectionAddr s) (elfSectionData s)

------------------------------------------------------------------------
--

-- | This command is called when reopt is called with no specific
-- action.
performReopt :: Args -> IO ()
performReopt args = do
  let output_path = args^.outputPath
  case takeExtension output_path of
    ".bc" -> do
      logger $
        "Generating '.bc' (LLVM ASCII assembly) is not supported!\n" ++
        "Use '.ll' extension to get assembled LLVM bitcode, and then " ++
        "use 'llvm-as out.ll' to generate an 'out.bc' file."
      exitFailure
    ".blocks" -> do
      writeFile output_path =<< showCFG args
    ".fns" -> do
      (os, disc_info, _) <-
          discoverX86Binary (args^.programPath) (args^.loadOpts) (args^.discOpts) (args^.includeAddrs) (args^.excludeAddrs)
      fns <- getFns logger (osPersonality os) disc_info
      writeFile output_path $ show (vcat (pretty <$> fns))
    ".ll" -> do
        hPutStrLn stderr "Generating LLVM"
        (os, disc_info, addrSymMap) <-
          discoverX86Binary (args^.programPath) (args^.loadOpts) (args^.discOpts) (args^.includeAddrs) (args^.excludeAddrs)
        fns <- getFns logger (osPersonality os) disc_info
        let llvmVer = args^.llvmVersion
        let archOps = LLVM.x86LLVMArchOps (show os)
        let Right llvmNmFun = LLVM.llvmFunctionName addrSymMap "reopt"
        let obj_llvm = llvmAssembly llvmVer $ LLVM.moduleForFunctions archOps llvmNmFun fns
        writeFileBuilder output_path obj_llvm
    ".o" -> do
      (os, disc_info, addrSymMap) <-
        discoverX86Binary (args^.programPath) (args^.loadOpts) (args^.discOpts) (args^.includeAddrs) (args^.excludeAddrs)
      fns <- getFns logger (osPersonality os) disc_info
      let llvmVer = args^.llvmVersion
      let archOps = LLVM.x86LLVMArchOps (show os)
      let Right llvmNmFun = LLVM.llvmFunctionName addrSymMap "reopt"
      let obj_llvm = llvmAssembly llvmVer $ LLVM.moduleForFunctions archOps llvmNmFun fns
      objContents <- compileLLVM (args^.optLevel) (args^.optPath) (args^.llcPath) (args^.llvmMcPath) (osLinkName os) obj_llvm
      BS.writeFile output_path objContents
    ".s" -> do
        logger $
          "Generating '.s' (LLVM ASCII assembly) is not supported!\n" ++
          "Use '.ll' extension to get assembled LLVM bitcode, and then " ++
          "compile to generate a .s file."
        exitFailure
    _ -> do
        (orig_binary, os, disc_info, addrSymMap, _) <-
          discoverX86Elf (args^.programPath) (args^.loadOpts) (args^.discOpts) (args^.includeAddrs) (args^.excludeAddrs)
        fns <- getFns logger (osPersonality os) disc_info
        let llvmVer = args^.llvmVersion
        let archOps = LLVM.x86LLVMArchOps (show os)
        let Right llvmNmFun = LLVM.llvmFunctionName addrSymMap "reopt"
        let obj_llvm = llvmAssembly llvmVer $ LLVM.moduleForFunctions archOps llvmNmFun fns
        objContents <-
          compileLLVM (args^.optLevel) (args^.optPath) (args^.llcPath) (args^.llvmMcPath) (osLinkName os) obj_llvm

        new_obj <- parseElf64 "new object" objContents
        logger "Start merge and write"
        -- Convert binary to LLVM
        let tgts = discoveryControlFlowTargets disc_info
            redirs = addrRedirection tgts llvmNmFun <$> fns
        -- Merge and write out
        mergeAndWrite (args^.outputPath) orig_binary new_obj redirs

main' :: IO ()
main' = do
  args <- getCommandLineArgs
  setDebugKeys (args ^. debugKeys)
  case args^.reoptAction of
    DumpDisassembly -> do
      dumpDisassembly (args^.programPath)
    ShowCFG -> putStrLn =<< showCFG args
    ShowFunctions -> do
      showFunctions args
    ShowHelp -> do
      print $ helpText [] HelpFormatAll arguments
    ShowVersion ->
      putStrLn (modeHelp arguments)
    Relink -> do
      performRelink args
    Reopt -> do
      performReopt args

main :: IO ()
main = main' `catch` h
  where h e
          | isUserError e = do
            hPutStrLn stderr "User error"
            hPutStrLn stderr $ ioeGetErrorString e
          | otherwise = do
            hPutStrLn stderr "Other error"
            hPutStrLn stderr $ show e
            hPutStrLn stderr $ show (ioeGetErrorType e)
