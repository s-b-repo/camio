# Camio plugins

Camio's native app (`camio app`) discovers **process-based plugins** from this
directory. Each plugin is a subfolder containing a `plugin.json` manifest:

```json
{
  "name": "Uppercase",
  "description": "What it does",
  "kind": "transform",
  "command": ["python3", "run.py"]
}
```

When you run a plugin, Camio writes the selected input to the command's **stdin**
and shows its **stdout** as the result. Because each plugin is a separate OS
process, it can be written in any language and cannot touch Camio's memory.

**Trust model:** a plugin runs an arbitrary command with your privileges. Camio
runs a plugin only when you explicitly click *Run*, and shows the exact command
first. Treat third-party plugins as untrusted code and review the manifest before
running them.

The two bundled demos (`uppercase/`, `rot13/`) use coreutils `tr`, so they work
without any interpreter installed.
