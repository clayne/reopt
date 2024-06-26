/**
 * Logic for handling messages coming from the activity webview.
*/

import { ExecFileException } from 'child_process'
import * as fs from 'fs'
import * as path from 'path'

import { option } from 'fp-ts'
import { Tail } from 'tail'
import * as vscode from 'vscode'

import * as AW2E from '@shared/activity-webview-to-extension'
import * as E2AW from '@shared/extension-to-activity-webview'
import * as E2VCGW from '@shared/extension-to-reopt-vcg-webview'
import * as Interfaces from '@shared/interfaces'
import * as WorkspaceState from '@shared/workspace-state'

import { createReoptProject } from './create-reopt-project'
import {
    openReoptProject,
    openReoptProjectViaDialog,
} from './open-reopt-project'
import * as reopt from './reopt'
import * as reoptVCG from './reopt-vcg'


async function openOutputFile(outputFile: string): Promise<void> {
    const absoluteUri = vscode.Uri.file(path.resolve(outputFile))
    const doc = await vscode.workspace.openTextDocument(absoluteUri)
    await vscode.window.showTextDocument(doc, {
        preview: false,
    })
}


/** Just like vscode.OutputChannel, but the 'dispose' method is hidden. */
export type PrivateOutputChannel =
    Pick<vscode.OutputChannel, 'appendLine' | 'show'>
/**
 * When the user switches reopt projects, we drop the output channel for the
 * project to be closed, and open a new output channel for the project to be
 * opened.  This way, the messages in the output pane are always relevant to the
 * currently opened project.
 */
export type ReplaceOutputChannel =
    (newChannel: string) => PrivateOutputChannel


function makeDisplayError(
    replaceOutputChannel: ReplaceOutputChannel,
): (err: ExecFileException) => void {
    return (err) => {
        const channel = replaceOutputChannel('reopt error')
        // in my experience so far, the 'stack' has strictly more information
        // when present
        if (err.stack) {
            channel.appendLine(err.stack)

        } else {
            channel.appendLine(err.message)
        }
        channel.appendLine('The following command errored, scroll up for error messages.')
        channel.appendLine(err.cmd || 'No command, please report.')
        channel.show()
    }
}


/**
 * Returns a string that can be displayed to the user while reopt is running in
 * a given mode.
 * @param reoptMode - Mode reopt is running in
 * @returns User-friendly string description
 */
function getTitleForReoptMode(
    reoptMode: reopt.ReoptMode,
): string {
    switch (reoptMode) {
        case reopt.ReoptMode.GenerateCFG: return 'Generating CFG...'
        case reopt.ReoptMode.GenerateDisassembly: return 'Generating disassembly...'
        case reopt.ReoptMode.GenerateFunctions: return 'Generating functions...'
        case reopt.ReoptMode.GenerateLLVM: return 'Generating LLVM...'
    }
}



/**
 * Contains the shared logic for calling reopt and updating the IDE state, for
 * all interesting modes in which we can run reopt.
 * @param context - VSCode extension context
 * @param diagnosticCollection - current diagnostic collection
 * @param replaceOutputChannel - cf. 'ReplaceOutputChannel'
 * @returns Given a reopt mode, returns a function that runs reopt in that mode,
 * and displays the results.
 */
function makeReoptGenerate(
    context: vscode.ExtensionContext,
    diagnosticCollection: vscode.DiagnosticCollection,
    replaceOutputChannel: ReplaceOutputChannel,
    reoptVCGWebviewPromise: Promise<Interfaces.ReoptVCGWebview>,
): (reoptMode: reopt.ReoptMode) => void {

    return (reoptMode) => {

        vscode.window

            .withProgress(
                {
                    location: vscode.ProgressLocation.Notification,
                    title: getTitleForReoptMode(reoptMode),
                    cancellable: true,
                },
                // TODO: we can probably kill the child process upon cancellation
                (_progress, _token) => reopt.runReoptToGenerateFile(context, reoptMode)
            )

            .then(
                // on fulfilled
                processOutputAndEvents(context, diagnosticCollection, reoptMode, reoptVCGWebviewPromise),
                // on rejected
                makeDisplayError(replaceOutputChannel),
            )

    }

}


/**
 *
 * @param context - VSCode extension context
 * @param webview - Extension webview
 * @param diagnosticCollection - Current diagnostic collection
 * @param replaceConfigurationWatcher - While a reopt project is open, we have a
 * filesystem watcher for its project file.  When a different project is open,
 * we call this to replace the old watcher with a new one.
 * @param replaceOutputChannel - see [[ReplaceOutputChannel]]
 * @returns
 */
export function makeMessageHandler(
    context: vscode.ExtensionContext,
    activityWebview: Interfaces.ActivityWebview,
    diagnosticCollection: vscode.DiagnosticCollection,
    reoptVCGWebviewPromise: Promise<Interfaces.ReoptVCGWebview>,
    replaceConfigurationWatcher: (w?: vscode.FileSystemWatcher) => void,
    replaceOutputChannel: ReplaceOutputChannel,
): (m: AW2E.ActivityWebviewToExtension) => Promise<void> {

    const reoptGenerate = makeReoptGenerate(
        context,
        diagnosticCollection,
        replaceOutputChannel,
        reoptVCGWebviewPromise,
    )

    const resetProject = () => {
        WorkspaceState.clearVariable(context, WorkspaceState.reoptProjectConfiguration)
        WorkspaceState.clearVariable(context, WorkspaceState.reoptProjectFile)
        WorkspaceState.clearVariable(context, WorkspaceState.reoptVCGEntries)
        activityWebview.postMessage(
            { tag: E2AW.closedProjectTag } as E2AW.ClosedProject
        )
        reoptVCGWebviewPromise.then(w =>
            w.postMessage(
                {
                    tag: E2VCGW.Tags.setReoptVCGEntries,
                    entries: [],
                } as E2VCGW.SetReoptVCGEntries
            )
        )
    }

    return async (message: AW2E.ActivityWebviewToExtension) => {

        switch (message.tag) {

            case AW2E.closeProject: {
                resetProject()
                replaceConfigurationWatcher(undefined)
                return
            }

            case AW2E.createProjectFile: {
                resetProject()
                const reoptProjectFile = await createReoptProject()
                const watcher = await openReoptProject(context, activityWebview, reoptProjectFile)
                replaceConfigurationWatcher(watcher)
                return
            }

            case AW2E.generateCFG: {
                reoptGenerate(reopt.ReoptMode.GenerateCFG)
                return
            }

            // case W2E.generateDisassembly: {
            //     reoptGenerate(reopt.ReoptMode.GenerateObject)
            //     return
            // }

            case AW2E.generateFunctions: {
                reoptGenerate(reopt.ReoptMode.GenerateFunctions)
                return
            }

            case AW2E.generateLLVM: {
                reoptGenerate(reopt.ReoptMode.GenerateLLVM)
                return
            }

            case AW2E.jumpToSymbol: {
                const { fsPath, range } = message.symbol

                const doc = await vscode.workspace.openTextDocument(fsPath)
                const editor = await vscode.window.showTextDocument(doc)
                const startPosition = new vscode.Position(range.start.line, range.start.character)
                const endPosition = new vscode.Position(range.end.line, range.end.character)

                // Move symbol into view and select it
                editor.selection = new vscode.Selection(startPosition, endPosition)
                editor.revealRange(
                    new vscode.Range(startPosition, endPosition),
                    vscode.TextEditorRevealType.AtTop,
                )

                return
            }

            case AW2E.openProject: {
                resetProject()
                const watcher = await openReoptProjectViaDialog(context, activityWebview)
                replaceConfigurationWatcher(watcher)
                return
            }

            case AW2E.showProjectFile: {
                const projectFile = WorkspaceState.readReoptProjectFile(context)
                if (projectFile === undefined) {
                    // this should not be possible, but just in case...
                    vscode.window.showErrorMessage(
                        'Could not show project file: please reopen the project.',
                    )
                    return
                }
                const doc = await vscode.workspace.openTextDocument(projectFile)
                await vscode.window.showTextDocument(doc)

                return
            }

            // forces exhaustivity checking
            default: {
                const exhaustiveCheck: never = message
                throw new Error(`Unhandled color case: ${exhaustiveCheck}`)
            }

        }
    }
}


/**
 * Reopt generates an events file when running.  This processes it, displaying
 * relevant information to the user at the end of a run: what errors happened in
 * the process and where/why.
 * @param context - VSCode extension context
 * @param diagnosticsCollection - Current diagnostics collection
 * @param eventsFile - The generated events file
 */
async function processEventsFile(
    context: vscode.ExtensionContext,
    diagnosticsCollection: vscode.DiagnosticCollection,
    eventsFile: fs.PathLike,
): Promise<void> {

    // We need the disassembly file to show errors.  This makes sure that it has
    // been generated.
    const disassemblyFile = await reopt.runReoptToGenerateDisassembly(context)

    reopt.displayReoptEventsAsDiagnostics(
        context,
        diagnosticsCollection,
        disassemblyFile,
        eventsFile,
    )

}


function processOutputAndEvents(
    context: vscode.ExtensionContext,
    diagnosticCollection: vscode.DiagnosticCollection,
    reoptMode: reopt.ReoptMode,
    reoptVCGWebviewPromise: Promise<Interfaces.ReoptVCGWebview>,
): (files: Interfaces.OutputAndEventsFiles) => Promise<void> {
    return async ({
        outputFile,
        eventsFile,
    }) => {

        openOutputFile(outputFile)
        processEventsFile(context, diagnosticCollection, eventsFile)

        // Then, if the file was LLVM, we can run reopt-vcg
        if (reoptMode !== reopt.ReoptMode.GenerateLLVM) { return }

        const projectConfiguration = WorkspaceState.readReoptProjectConfiguration(context)
        if (!projectConfiguration) { return }
        const projectName = projectConfiguration.name
        const annotationsFile = projectConfiguration.annotations
        if (option.isNone(projectName)) { return }

        // Cannot run reopt-vcg if there is no annotations file
        if (option.isNone(annotationsFile)) {
            vscode.window.showErrorMessage(
                'Not running reopt-vcg because the configuration does not specify an annotations file.'
            )
            return
        }

        const workingDirectory = path.dirname(projectConfiguration.binaryFile)

        const resolvedAnnotationsFile = path.resolve(workingDirectory, annotationsFile.value)

        if (!fs.existsSync(resolvedAnnotationsFile)) {
            vscode.window.showErrorMessage(
                `Not running reopt-vcg because the annotations file does not exist: ${annotationsFile.value} resolved to ${resolvedAnnotationsFile}`
            )
            return
        }

        // We also need a handler to the reopt-vcg webview to send the results
        // to.
        // FIXME: I'm worried that if the user has never clicked on the panel
        // that shows the result, we will stay here forever.
        const webview = await reoptVCGWebviewPromise

        // Tell the webview to forget about pre-existing entries
        webview.postMessage({
            tag: E2VCGW.Tags.setReoptVCGEntries,
            entries: [],
        } as E2VCGW.SetReoptVCGEntries)

        const jsonsFile = reopt.replaceExtensionWith('jsons')(annotationsFile.value)
        const resolvedJSONsFile = path.resolve(workingDirectory, jsonsFile)

        // Since we are going to start reading the file in parallel with
        // reopt-vcg starting to write into it, we better make sure it does not
        // contain old lines!
        fs.closeSync(fs.openSync(resolvedJSONsFile, 'w'))

        const entries: Interfaces.ReoptVCGEntry[] = []
        WorkspaceState.writeReoptVCGEntries(context, entries)

        /**
         * WARNING: Make sure to `unwatch` the file when reopt-vcg is done, or
         * you will have multiple watchers at the same time!
         */
        const tail = new Tail(resolvedJSONsFile, { fromBeginning: true })
        tail.on('line', line => {
            const entry = JSON.parse(line)
            entries.push(entry)
            WorkspaceState.writeReoptVCGEntries(context, entries)
            webview.postMessage({
                tag: E2VCGW.Tags.addReoptVCGEntry,
                entry,
            } as E2VCGW.AddReoptVCGEntry)
        })

        vscode.window
            .withProgress(
                {
                    location: vscode.ProgressLocation.Notification,
                    title: 'Running reopt-vcg',
                    cancellable: true,
                },
                // TODO: we can probably kill the child process upon cancellation
                (_progress, _token) => (
                    reoptVCG.runReoptVCG(
                        context,
                        {
                            annotationsFile: annotationsFile.value,
                            jsonsFile,
                        },
                    ).finally(() => {
                        tail.unwatch()
                    })
                )
            )

    }
}
