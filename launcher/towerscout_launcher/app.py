from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from typing import Callable

from .coordination import OperationGuard
from .discovery import build_repair_preview, choose_engine, collect_snapshot
from .exact_target_confirmation import (
    CONFIRMATION_TEXT,
    DEFAULT_CONFIRMATION_TIMEOUT_SECONDS,
    ExactTargetConfirmationCoordinator,
    ExactTargetConfirmationError,
    ExactTargetConfirmationTransaction,
)
from .models import LauncherSnapshot, PublicState
from .target_contracts import MapProvider

_STATE_COLORS = {
    PublicState.SUCCESS: "#157347",
    PublicState.UNAVAILABLE: "#8a6116",
    PublicState.ERROR: "#b02a37",
}
_USER_CONFIRMATION = CONFIRMATION_TEXT


def _build_default_repair_coordinator() -> ExactTargetConfirmationCoordinator:
    """Resolve, confirm, and execute one exact native repair transaction."""
    return ExactTargetConfirmationCoordinator()


class _TimedTypedConfirmationDialog(simpledialog.Dialog):
    """Modal typed confirmation that releases its target after a fixed timeout."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        title: str,
        prompt: str,
        timeout_seconds: float,
    ) -> None:
        self.prompt = prompt
        self.timeout_milliseconds = max(1, int(timeout_seconds * 1000))
        self.value: str | None = None
        self._timeout_id: str | None = None
        self._entry: ttk.Entry | None = None
        super().__init__(parent, title)

    def body(self, master: tk.Misc) -> tk.Widget:
        ttk.Label(master, text=self.prompt, justify=tk.LEFT, wraplength=680).pack(
            fill=tk.X, padx=6, pady=(4, 10)
        )
        self._entry = ttk.Entry(master, width=52)
        self._entry.pack(fill=tk.X, padx=6, pady=(0, 4))
        self._timeout_id = self.after(self.timeout_milliseconds, self.cancel)
        return self._entry

    def apply(self) -> None:
        if self._entry is not None:
            self.value = self._entry.get()

    def cancel(self, event: tk.Event[tk.Misc] | None = None) -> None:
        if self._timeout_id is not None:
            try:
                self.after_cancel(self._timeout_id)
            except tk.TclError:
                pass
            self._timeout_id = None
        super().cancel(event)


def _ask_typed_confirmation(parent: tk.Misc, prompt: str) -> str | None:
    dialog = _TimedTypedConfirmationDialog(
        parent,
        title="Confirm TowerScout TLS repair",
        prompt=prompt,
        timeout_seconds=DEFAULT_CONFIRMATION_TIMEOUT_SECONDS,
    )
    return dialog.value


class TowerScoutLauncherApp:
    def __init__(
        self,
        root: tk.Tk,
        *,
        snapshot_loader: Callable[[], LauncherSnapshot] = collect_snapshot,
        repair_coordinator: ExactTargetConfirmationCoordinator | None = None,
    ) -> None:
        self.root = root
        self.snapshot_loader = snapshot_loader
        self.snapshot: LauncherSnapshot | None = None
        self.repair_coordinator = (
            repair_coordinator
            if repair_coordinator is not None
            else _build_default_repair_coordinator()
        )
        self.operations = OperationGuard()
        self.provider_var = tk.StringVar(value="Google Maps")
        self.engine_var = tk.StringVar(value="")
        self.package_var = tk.StringVar(value="Inspecting package...")
        self.profile_var = tk.StringVar(value="Runtime profile unavailable")
        self.docker_var = tk.StringVar(value="Checking Docker...")
        self.podman_var = tk.StringVar(value="Checking Podman...")
        self.status_var = tk.StringVar(value="Checking TowerScout...")
        self.footer_var = tk.StringVar(value="No changes have been made.")
        self._build_window()
        self.root.after(50, self.refresh)

    def _build_window(self) -> None:
        self.root.title("TowerScout Launcher Prototype")
        self.root.geometry("800x760")
        self.root.minsize(720, 680)
        self.root.configure(background="#f5f7fa")

        style = ttk.Style(self.root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Header.TLabel", font=("Segoe UI Semibold", 20))
        style.configure("Subheader.TLabel", font=("Segoe UI Semibold", 11))
        style.configure("Body.TLabel", font=("Segoe UI", 10))
        style.configure("Badge.TLabel", foreground="#7a4b00", background="#fff3cd")

        outer = ttk.Frame(self.root, padding=22)
        outer.pack(fill=tk.BOTH, expand=True)
        ttk.Label(outer, text="TowerScout", style="Header.TLabel").pack(anchor=tk.W)
        ttk.Label(
            outer,
            text="CONTROLLED TLS REPAIR PROTOTYPE — UNSIGNED",
            style="Badge.TLabel",
            padding=(8, 4),
        ).pack(anchor=tk.W, pady=(5, 16))

        package_frame = ttk.LabelFrame(
            outer, text="Package and runtime profile", padding=12
        )
        package_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(
            package_frame, textvariable=self.package_var, style="Subheader.TLabel"
        ).pack(anchor=tk.W)
        ttk.Label(
            package_frame,
            textvariable=self.profile_var,
            style="Body.TLabel",
            wraplength=680,
        ).pack(anchor=tk.W, pady=(4, 0))

        runtime_frame = ttk.LabelFrame(outer, text="Container runtimes", padding=12)
        runtime_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(runtime_frame, textvariable=self.docker_var).pack(anchor=tk.W)
        ttk.Label(runtime_frame, textvariable=self.podman_var).pack(
            anchor=tk.W, pady=(4, 0)
        )

        status_frame = ttk.LabelFrame(outer, text="TowerScout status", padding=12)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        self.status_label = tk.Label(
            status_frame,
            textvariable=self.status_var,
            anchor=tk.W,
            justify=tk.LEFT,
            background="white",
            foreground=_STATE_COLORS[PublicState.UNAVAILABLE],
            font=("Segoe UI", 10),
        )
        self.status_label.pack(fill=tk.X)

        preview_frame = ttk.LabelFrame(
            outer, text="Check / repair map connections", padding=12
        )
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        controls = ttk.Frame(preview_frame)
        controls.pack(fill=tk.X)
        ttk.Label(controls, text="Provider:").grid(row=0, column=0, sticky=tk.W)
        self.provider_box = ttk.Combobox(
            controls,
            textvariable=self.provider_var,
            values=("Google Maps", "Azure Maps"),
            state="readonly",
            width=18,
        )
        self.provider_box.grid(row=0, column=1, sticky=tk.W, padx=(8, 20))
        ttk.Label(controls, text="Target runtime:").grid(row=0, column=2, sticky=tk.W)
        self.engine_box = ttk.Combobox(
            controls,
            textvariable=self.engine_var,
            values=(),
            state="readonly",
            width=14,
        )
        self.engine_box.grid(row=0, column=3, sticky=tk.W, padx=(8, 0))
        self.preview_text = tk.Text(
            preview_frame,
            height=10,
            wrap=tk.WORD,
            state=tk.DISABLED,
            background="#ffffff",
            foreground="#263238",
            relief=tk.FLAT,
            padx=8,
            pady=8,
            font=("Segoe UI", 10),
        )
        self.preview_text.pack(fill=tk.BOTH, expand=True, pady=(12, 8))
        action_buttons = ttk.Frame(preview_frame)
        action_buttons.pack(fill=tk.X)
        self.preview_button = ttk.Button(
            action_buttons, text="Show repair plan", command=self.show_preview
        )
        self.preview_button.pack(side=tk.RIGHT)
        self.repair_button = ttk.Button(
            action_buttons,
            text="Repair TLS and restart...",
            command=self.repair_tls_and_restart,
        )
        self.repair_button.pack(side=tk.RIGHT, padx=(0, 8))

        footer = ttk.Frame(outer)
        footer.pack(fill=tk.X)
        ttk.Label(footer, textvariable=self.footer_var).pack(side=tk.LEFT)
        ttk.Button(footer, text="Refresh status", command=self.refresh).pack(
            side=tk.RIGHT
        )

    def _set_busy(self, busy: bool) -> None:
        cursor = "wait" if busy else ""
        self.root.configure(cursor=cursor)
        self.preview_button.configure(state=tk.DISABLED if busy else tk.NORMAL)
        self.repair_button.configure(state=tk.DISABLED if busy else tk.NORMAL)
        self.root.update_idletasks()

    def _replace_preview_text(self, title: str, body: str) -> None:
        self.preview_text.configure(state=tk.NORMAL)
        self.preview_text.delete("1.0", tk.END)
        self.preview_text.insert(tk.END, f"{title}\n\n{body}")
        self.preview_text.configure(state=tk.DISABLED)

    def refresh(self) -> None:
        with self.operations.begin() as started:
            if not started:
                self.footer_var.set("A launcher operation is already in progress.")
                return
            self._set_busy(True)
            self.footer_var.set("Running fixed, read-only status checks...")
            try:
                snapshot = self.snapshot_loader()
            except (
                Exception
            ):  # Public UI deliberately receives no raw exception detail.
                self.snapshot = None
                self.package_var.set("TowerScout package unavailable")
                self.profile_var.set("The package identity could not be verified.")
                self.docker_var.set("Docker: status unavailable")
                self.podman_var.set("Podman: status unavailable")
                self.status_var.set(
                    "Launcher inspection failed safely. No changes were made."
                )
                self.status_label.configure(foreground=_STATE_COLORS[PublicState.ERROR])
                self.footer_var.set(
                    "Error state is sanitized; use existing support commands."
                )
                return
            finally:
                self._set_busy(False)

            self.snapshot = snapshot
            package = snapshot.package
            self.package_var.set(package.package_label)
            selected = choose_engine(snapshot)
            engine_values = tuple(
                "Docker" if item.engine == "docker" else "Podman"
                for item in snapshot.runtimes
                if item.installed
            )
            self.engine_box.configure(values=engine_values)
            selected_label = (
                "Docker" if selected == "docker" else "Podman" if selected else ""
            )
            if selected_label and selected_label in engine_values:
                self.engine_var.set(selected_label)
            elif len(engine_values) == 1:
                self.engine_var.set(engine_values[0])
            else:
                self.engine_var.set("")
            engine_summary = selected_label or "choose Docker or Podman"
            selected_device = (
                snapshot.towerscout.selected_device.upper() or package.gpu_mode.upper()
            )
            digest = package.image_digest or "digest unavailable"
            self.profile_var.set(
                f"Target: {engine_summary} | device {selected_device} | port {package.port} | "
                f"image {package.image} | {digest}"
            )
            runtime_by_name = {item.engine: item for item in snapshot.runtimes}
            self.docker_var.set(f"Docker: {runtime_by_name['docker'].public_message}")
            self.podman_var.set(f"Podman: {runtime_by_name['podman'].public_message}")
            self.status_var.set(snapshot.towerscout.public_message)
            self.status_label.configure(
                foreground=_STATE_COLORS[snapshot.towerscout.state]
            )
            self.footer_var.set("Status refreshed. No changes were made.")

    def show_preview(self) -> None:
        with self.operations.begin() as started:
            if not started:
                self.footer_var.set("A launcher operation is already in progress.")
                return
            if self.snapshot is None:
                self.footer_var.set("Refresh status before creating a preview.")
                return
            provider = "google" if self.provider_var.get() == "Google Maps" else "azure"
            engine = self.engine_var.get().strip().lower()
            preview = build_repair_preview(
                self.snapshot, provider=provider, engine=engine
            )
            self._replace_preview_text(preview.title, preview.body)
            self.footer_var.set(
                "Preview created. No repair or runtime change was performed."
            )

    def repair_tls_and_restart(self) -> None:
        with self.operations.begin() as started:
            if not started:
                self.footer_var.set("A launcher operation is already in progress.")
                return
            if self.snapshot is None:
                self.footer_var.set("Refresh status before repairing TowerScout.")
                return
            provider = (
                MapProvider.GOOGLE
                if self.provider_var.get() == "Google Maps"
                else MapProvider.AZURE
            )
            self._set_busy(True)
            self.footer_var.set(
                "Resolving and retaining one exact Windows-trusted target..."
            )
            self.root.update_idletasks()
            transaction: ExactTargetConfirmationTransaction | None = None
            try:
                transaction = self.repair_coordinator.prepare(provider)
                typed = _ask_typed_confirmation(
                    self.root,
                    transaction.summary.render()
                    + "\n\nType REPAIR TLS AND RESTART to continue. "
                    "Anything else cancels without a change.",
                )
                if typed != _USER_CONFIRMATION:
                    self.repair_coordinator.cancel(transaction)
                    self.footer_var.set("Repair cancelled. No changes were made.")
                    self._replace_preview_text(
                        "TLS repair cancelled",
                        "The required confirmation was not entered. No changes "
                        "were made.",
                    )
                    return
                self.repair_coordinator.confirm(transaction, typed)
                self.repair_coordinator.execute(transaction)
                success_message = (
                    "TLS repair completed and TowerScout restarted successfully."
                )
                self.footer_var.set(success_message)
                self._replace_preview_text("TLS repair succeeded", success_message)
                messagebox.showinfo(
                    "TowerScout TLS repair",
                    success_message,
                    parent=self.root,
                )
            except ExactTargetConfirmationError as exc:
                messagebox.showerror(
                    "TowerScout TLS repair",
                    exc.public_message,
                    parent=self.root,
                )
                if transaction is None:
                    self._replace_preview_text(
                        "TLS repair did not start",
                        exc.public_message + " No changes were made.",
                    )
                self.footer_var.set(exc.public_message)
            except Exception:
                self.footer_var.set(
                    "The repair failed safely. Use the Task-086 manual recovery path."
                )
                self._replace_preview_text(
                    "TLS repair needs recovery",
                    "The repair failed safely. Use the Task-086 manual recovery "
                    "path; named volumes were not intentionally removed.",
                )
                messagebox.showerror(
                    "TowerScout TLS repair",
                    "The repair failed safely. Use the Task-086 manual recovery path.",
                    parent=self.root,
                )
            finally:
                if transaction is not None:
                    try:
                        transaction.close()
                    except ExactTargetConfirmationError:
                        pass
                self._set_busy(False)


def run_app() -> int:
    root = tk.Tk()
    TowerScoutLauncherApp(root)
    root.mainloop()
    return 0


def show_duplicate_instance_message() -> None:
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo(
        "TowerScout Launcher",
        "TowerScout Launcher is already open. Use the existing window.",
        parent=root,
    )
    root.destroy()


def show_startup_recovery_message(message: str, *, failed: bool) -> None:
    """Show one fixed, sanitized startup recovery outcome."""

    root = tk.Tk()
    root.withdraw()
    show = messagebox.showerror if failed else messagebox.showinfo
    show(
        "TowerScout repair recovery",
        message,
        parent=root,
    )
    root.destroy()
