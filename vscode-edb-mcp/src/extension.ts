import * as vscode from "vscode";
import { spawn, ChildProcess } from "child_process";
import * as path from "path";

// ── MCP Transport ────────────────────────────────────────────────────────────

interface MCPError {
  code?: number;
  message: string;
}

interface MCPResponse {
  id?: number;
  result?: any;
  error?: MCPError;
}

interface MCPToolResult {
  content: { type: string; text: string }[];
  isError: boolean;
}

class MCPTransport {
  private _process: ChildProcess | null = null;
  private _requestId = 0;
  private _pending = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void }>();
  private _buffer = "";
  private _onLog: (msg: string) => void;

  constructor(onLog: (msg: string) => void) {
    this._onLog = onLog;
  }

  get isRunning(): boolean {
    return this._process !== null && this._process.exitCode === null;
  }

  start(python: string, scriptPath: string): Promise<string> {
    if (this.isRunning) return Promise.resolve("Already running");

    this._process = spawn(python, [scriptPath], {
      stdio: ["pipe", "pipe", "pipe"],
      cwd: path.dirname(scriptPath),
    });

    const proc = this._process;

    proc.stdout?.on("data", (chunk: Buffer) => {
      this._buffer += chunk.toString("utf-8");
      this._processBuffer();
    });

    proc.stderr?.on("data", (chunk: Buffer) => {
      this._onLog(`[stderr] ${chunk.toString("utf-8").trim()}`);
    });

    proc.on("exit", (code) => {
      this._onLog(`Server exited with code ${code}`);
      for (const [id, pending] of this._pending) {
        pending.reject(new Error(`Server exited with code ${code}`));
      }
      this._pending.clear();
    });

    proc.on("error", (err) => {
      this._onLog(`Server error: ${err.message}`);
    });

    return this._request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "vscode-edb-mcp", version: "1.0.0" },
    }).then((result) => {
      this._notify("notifications/initialized");
      const serverName = result?.serverInfo?.name ?? "unknown";
      return `Connected: ${serverName}`;
    });
  }

  stop(): void {
    if (!this._process) return;
    this._notify("exit");
    const proc = this._process;
    proc.stdin?.end();
    const killTimer = setTimeout(() => {
      if (proc.exitCode === null) proc.kill();
    }, 5000);
    proc.on("exit", () => clearTimeout(killTimer));
    this._process = null;
  }

  listTools(): Promise<any[]> {
    return this._request("tools/list", {}).then((r) => r?.tools ?? []);
  }

  callTool(name: string, arguments_: Record<string, any> = {}): Promise<MCPToolResult> {
    return this._request("tools/call", {
      name,
      arguments: { params: arguments_ },
    }).then((result) => ({
      content: result?.content ?? [],
      isError: result?.isError ?? false,
    }));
  }

  private _request(method: string, params: any): Promise<any> {
    return new Promise((resolve, reject) => {
      this._requestId++;
      const id = this._requestId;
      const msg = JSON.stringify({
        jsonrpc: "2.0",
        id,
        method,
        params,
      });
      this._pending.set(id, { resolve, reject });
      this._write(msg);
    });
  }

  private _notify(method: string): void {
    const msg = JSON.stringify({ jsonrpc: "2.0", method });
    this._write(msg);
  }

  private _write(msg: string): void {
    if (!this._process?.stdin) {
      this._onLog("MCP transport not connected");
      return;
    }
    this._process.stdin.write(msg + "\n");
  }

  private _processBuffer(): void {
    const lines = this._buffer.split("\n");
    this._buffer = lines.pop() ?? "";
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const parsed: MCPResponse = JSON.parse(trimmed);
        if (parsed.id !== undefined && this._pending.has(parsed.id)) {
          const pending = this._pending.get(parsed.id)!;
          this._pending.delete(parsed.id);
          if (parsed.error) {
            pending.reject(new Error(parsed.error.message ?? JSON.stringify(parsed.error)));
          } else {
            pending.resolve(parsed.result);
          }
        } else if (parsed.id === undefined) {
          // server notification / log, ignore
        }
      } catch {
        this._onLog(`[parse] ${trimmed}`);
      }
    }
  }
}

// ── WebView Panel ────────────────────────────────────────────────────────────

function getPanelHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EDB Debugger</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: var(--vscode-font-family); background: var(--vscode-editor-background); color: var(--vscode-editor-foreground); padding: 16px; }
h1 { font-size: 18px; margin-bottom: 12px; color: var(--vscode-titleBar-activeForeground); }
.section { margin-bottom: 16px; }
.section-title { font-size: 13px; font-weight: 600; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.8; }
.btn-row { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 8px; }
button { background: var(--vscode-button-background); color: var(--vscode-button-foreground); border: none; padding: 6px 12px; font-size: 12px; cursor: pointer; border-radius: 2px; font-family: inherit; }
button:hover { background: var(--vscode-button-hoverBackground); }
button.secondary { background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground); }
button.secondary:hover { background: var(--vscode-button-secondaryHoverBackground); }
button.danger { background: #c53030; color: #fff; }
button.danger:hover { background: #9b2c2c; }
textarea { width: 100%; background: var(--vscode-input-background); color: var(--vscode-input-foreground); border: 1px solid var(--vscode-input-border); padding: 8px; font-family: var(--vscode-editor-font-family); font-size: 12px; resize: vertical; }
.output { background: var(--vscode-terminal-background); color: var(--vscode-terminal-foreground); padding: 8px; font-family: var(--vscode-editor-font-family); font-size: 11px; white-space: pre-wrap; overflow-x: auto; max-height: 400px; overflow-y: auto; border: 1px solid var(--vscode-panel-border); margin-top: 4px; }
label { display: block; margin-bottom: 4px; font-size: 12px; }
input[type="text"] { width: 100%; background: var(--vscode-input-background); color: var(--vscode-input-foreground); border: 1px solid var(--vscode-input-border); padding: 4px 6px; font-family: var(--vscode-editor-font-family); font-size: 12px; margin-bottom: 6px; }
.status { display: flex; align-items: center; gap: 6px; font-size: 12px; margin-bottom: 12px; }
.indicator { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
.indicator.on { background: #4caf50; }
.indicator.off { background: #666; }
</style>
</head>
<body>
<div class="status" id="statusBar">
  <span class="indicator off" id="statusIndicator"></span>
  <span id="statusText">Disconnected</span>
</div>

<h1>EDB Debugger</h1>

<div class="section">
  <div class="section-title">Execution</div>
  <div class="btn-row">
    <button onclick="command('loadBinary')">Load Binary</button>
    <button onclick="command('run')">Run</button>
    <button onclick="command('pause')">Pause</button>
    <button class="secondary" onclick="command('restart')">Restart</button>
    <button class="danger" onclick="command('kill')">Kill</button>
  </div>
</div>

<div class="section">
  <div class="section-title">Stepping</div>
  <div class="btn-row">
    <button onclick="command('stepInto')">Step Into</button>
    <button onclick="command('stepOver')">Step Over</button>
    <button class="secondary" onclick="command('stepOut')">Step Out</button>
  </div>
</div>

<div class="section">
  <div class="section-title">Breakpoints</div>
  <div class="btn-row">
    <button onclick="command('toggleBreakpoint')">Toggle BP at Cursor</button>
    <button onclick="command('listBreakpoints')">List BPs</button>
    <button class="secondary" onclick="command('clearBreakpoints')">Clear All BPs</button>
  </div>
  <input type="text" id="bpAddress" placeholder="Address or symbol (e.g. main or 0x401000)" />
  <div class="btn-row">
    <button onclick="command('setBreakpoint')">Set BP</button>
    <button class="secondary" onclick="command('setHwBreakpoint')">Set HW BP</button>
  </div>
</div>

<div class="section">
  <div class="section-title">Inspection</div>
  <div class="btn-row">
    <button onclick="command('registers')">Registers</button>
    <button onclick="command('stack')">Stack</button>
    <button onclick="command('backtrace')">Backtrace</button>
    <button onclick="command('memoryMap')">Memory Map</button>
    <button onclick="command('disasm')">Disassemble at PC</button>
    <button onclick="command('locals')">Locals</button>
    <button onclick="command('threads')">Threads</button>
  </div>
</div>

<div class="section">
  <div class="section-title">Memory</div>
  <input type="text" id="memAddress" placeholder="Address (e.g. 0x7fff0000)" />
  <div class="btn-row">
    <button onclick="command('readMemory')">Read</button>
  </div>
</div>

<div class="section">
  <div class="section-title">Expression</div>
  <input type="text" id="exprInput" placeholder="e.g. $rax + 8  or  *(int*)0x401000" />
  <div class="btn-row">
    <button onclick="command('evaluate')">Evaluate</button>
  </div>
</div>

<div class="section">
  <div class="section-title">Output</div>
  <textarea id="outputArea" rows="10" readonly></textarea>
</div>

<script>
const vscode = acquireVsCodeApi();

function command(cmd) {
  let args = {};
  switch (cmd) {
    case 'loadBinary':
      const bpPath = document.getElementById('bpAddress').value;
      const loadPath = bpPath || prompt('Binary path:');
      if (!loadPath) return;
      args = { path: loadPath };
      cmd = 'loadBinary';
      break;
    case 'setBreakpoint':
      args = { address: document.getElementById('bpAddress').value };
      if (!args.address) return alert('Enter an address or symbol');
      cmd = 'setBreakpoint';
      break;
    case 'setHwBreakpoint':
      args = { address: document.getElementById('bpAddress').value };
      if (!args.address) return alert('Enter an address or symbol');
      cmd = 'setHardwareBreakpoint';
      break;
    case 'readMemory':
      args = { address: document.getElementById('memAddress').value };
      if (!args.address) return alert('Enter a memory address');
      cmd = 'readMemory';
      break;
    case 'evaluate':
      args = { expression: document.getElementById('exprInput').value };
      if (!args.expression) return alert('Enter an expression');
      cmd = 'evaluateExpression';
      break;
    case 'disasm':
      cmd = 'disassemble';
      break;
    case 'toggleBreakpoint':
      cmd = 'toggleBreakpoint';
      break;
    case 'listBreakpoints':
      cmd = 'listBreakpoints';
      break;
    case 'clearBreakpoints':
      cmd = 'clearBreakpoints';
      break;
    default:
      break;
  }
  vscode.postMessage({ command: cmd, args });
}

window.addEventListener('message', event => {
  const msg = event.data;
  switch (msg.type) {
    case 'status':
      document.getElementById('statusText').textContent = msg.text;
      const indicator = document.getElementById('statusIndicator');
      indicator.className = 'indicator ' + (msg.connected ? 'on' : 'off');
      break;
    case 'output':
      const area = document.getElementById('outputArea');
      area.value += msg.text + '\\n';
      area.scrollTop = area.scrollHeight;
      break;
    case 'clearOutput':
      document.getElementById('outputArea').value = '';
      break;
  }
});
</script>
</body>
</html>`;
}

// ── Extension Activation ─────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext) {
  const log = vscode.window.createOutputChannel("EDB Debugger");
  log.appendLine("EDB Debugger MCP extension activated");

  const transport = new MCPTransport((msg) => log.appendLine(msg));
  let webViewPanel: vscode.WebviewPanel | undefined;
  let serverCapabilities = { tools_count: 0 };

  // Status bar
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.text = "$(debug-disconnect) EDB: Disconnected";
  statusBar.tooltip = "Click to start EDB Bridge";
  statusBar.command = "edb-debugger-mcp.start";
  statusBar.show();
  context.subscriptions.push(statusBar);

  // ── helpers ──────────────────────────────────────────────────────────

  function updateStatus(connected: boolean, detail?: string) {
    if (connected) {
      statusBar.text = `$(debug) EDB: Connected (${serverCapabilities.tools_count} tools)`;
      statusBar.tooltip = detail ?? "Click to show debugger panel";
      statusBar.command = "edb-debugger-mcp.showPanel";
    } else {
      statusBar.text = "$(debug-disconnect) EDB: Disconnected";
      statusBar.tooltip = "Click to start EDB Bridge";
      statusBar.command = "edb-debugger-mcp.start";
    }
    postStatus(connected);
  }

  function postStatus(connected: boolean) {
    webViewPanel?.webview.postMessage({
      type: "status",
      connected,
      text: connected ? `Connected (${serverCapabilities.tools_count} tools)` : "Disconnected",
    });
  }

  function postOutput(text: string) {
    log.appendLine(text);
    webViewPanel?.webview.postMessage({ type: "output", text });
  }

  async function callAndShow(name: string, args?: Record<string, any>) {
    if (!transport.isRunning) {
      vscode.window.showWarningMessage("EDB Bridge is not running. Start it first.");
      return;
    }
    try {
      const result = await transport.callTool(name, args ?? {});
      const output = result.content.map((c) => c.text).join("\n");
      postOutput(`> ${name}\n${output}`);
      return result;
    } catch (err: any) {
      postOutput(`> ${name}\nERROR: ${err.message}`);
      vscode.window.showErrorMessage(`EDB tool failed: ${err.message}`);
    }
  }

  function showWebView() {
    if (webViewPanel) {
      webViewPanel.reveal(vscode.ViewColumn.Two);
      return;
    }
    webViewPanel = vscode.window.createWebviewPanel(
      "edbDebugger",
      "EDB Debugger",
      vscode.ViewColumn.Two,
      { enableScripts: true, retainContextWhenHidden: true }
    );
    webViewPanel.webview.html = getPanelHtml();
    webViewPanel.webview.onDidReceiveMessage(async (msg) => {
      switch (msg.command) {
        case "loadBinary":
          vscode.commands.executeCommand("edb-debugger-mcp.loadBinary");
          break;
        case "run":
          vscode.commands.executeCommand("edb-debugger-mcp.run");
          break;
        case "pause":
          vscode.commands.executeCommand("edb-debugger-mcp.pause");
          break;
        case "stepInto":
          vscode.commands.executeCommand("edb-debugger-mcp.stepInto");
          break;
        case "stepOver":
          vscode.commands.executeCommand("edb-debugger-mcp.stepOver");
          break;
        case "stepOut":
          callAndShow("edb_step_out");
          break;
        case "restart":
          callAndShow("edb_restart");
          break;
        case "kill":
          callAndShow("edb_kill_process");
          break;
        case "registers":
          callAndShow("edb_get_registers");
          break;
        case "stack":
          callAndShow("edb_get_stack");
          break;
        case "backtrace":
          callAndShow("edb_get_backtrace");
          break;
        case "memoryMap":
          callAndShow("edb_get_memory_map");
          break;
        case "disassemble":
          callAndShow("edb_disassemble", { address: "$pc", count: 16 });
          break;
        case "locals":
          callAndShow("edb_get_locals");
          break;
        case "threads":
          callAndShow("edb_list_threads");
          break;
        case "listBreakpoints":
          callAndShow("edb_list_breakpoints");
          break;
        case "clearBreakpoints":
          callAndShow("edb_remove_all_breakpoints");
          break;
        case "toggleBreakpoint":
          callAndShow("edb_toggle_breakpoint");
          break;
        case "setBreakpoint":
          callAndShow("edb_set_breakpoint", { address: msg.args?.address ?? "" });
          break;
        case "setHardwareBreakpoint":
          callAndShow("edb_set_hardware_breakpoint", { address: msg.args?.address ?? "" });
          break;
        case "readMemory":
          callAndShow("edb_read_memory", { address: msg.args?.address ?? "" });
          break;
        case "evaluateExpression":
          callAndShow("edb_evaluate_expression", { expression: msg.args?.expression ?? "" });
          break;
      }
    });
    webViewPanel.onDidDispose(() => {
      webViewPanel = undefined;
    });
    postStatus(transport.isRunning);
  }

  // ── commands ────────────────────────────────────────────────────────

  context.subscriptions.push(
    vscode.commands.registerCommand("edb-debugger-mcp.start", async () => {
      if (transport.isRunning) {
        vscode.window.showInformationMessage("EDB Bridge is already running");
        return;
      }
      const pythonPath = vscode.workspace.getConfiguration("edb-debugger-mcp").get<string>("pythonPath", "python3");
      const scriptPath = path.join(context.extensionPath, "..", "..", "edb_debugger_mcp.py");
      const absScript = path.resolve(
        vscode.workspace.getConfiguration("edb-debugger-mcp").get<string>("serverScript", scriptPath)
      );

      log.appendLine(`Starting EDB server: ${pythonPath} ${absScript}`);
      try {
        const msg = await transport.start(pythonPath, absScript);
        log.appendLine(msg);
        const tools = await transport.listTools();
        serverCapabilities.tools_count = tools.length;
        log.appendLine(`Loaded ${tools.length} tools`);
        updateStatus(true, msg);
        vscode.window.showInformationMessage(`EDB Bridge: ${msg} (${tools.length} tools)`);
        // Auto-show panel
        showWebView();
        postOutput(`Bridge started: ${msg}\n${tools.length} tools available`);
      } catch (err: any) {
        log.appendLine(`Start failed: ${err.message}`);
        updateStatus(false);
        vscode.window.showErrorMessage(`EDB Bridge failed: ${err.message}`);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("edb-debugger-mcp.stop", () => {
      transport.stop();
      serverCapabilities = { tools_count: 0 };
      updateStatus(false);
      postOutput("Bridge stopped");
      vscode.window.showInformationMessage("EDB Bridge stopped");
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("edb-debugger-mcp.showPanel", () => {
      showWebView();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("edb-debugger-mcp.loadBinary", async () => {
      const binary = await vscode.window.showInputBox({
        prompt: "Path to binary to debug",
        placeHolder: "/bin/ls",
      });
      if (!binary) return;
      await callAndShow("edb_load_program", { path: binary });
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("edb-debugger-mcp.run", () => {
      callAndShow("edb_run");
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("edb-debugger-mcp.pause", () => {
      callAndShow("edb_pause");
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("edb-debugger-mcp.stepInto", () => {
      callAndShow("edb_step_into");
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("edb-debugger-mcp.stepOver", () => {
      callAndShow("edb_step_over");
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("edb-debugger-mcp.showRegisters", async () => {
      const result = await callAndShow("edb_get_registers");
      // Also show in its own output channel
      if (result) {
        log.show();
      }
    })
  );
}

export function deactivate() {
  // Transport will be garbage-collected; the process will be orphaned.
  // Subprocess cleanup is handled on extension deactivation via the stop command.
}
