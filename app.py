"""
FactoryRecon - Aplicación de Escritorio para Descubrimiento de Equipos Ethernet en Windows.
Interfaz gráfica moderna construida con CustomTkinter y APIs nativas de Windows (sin requerir Npcap).
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox
import webbrowser
from typing import Optional

import customtkinter as ctk
from PIL import Image

from icon_gen import generate_rj45_assets
from scanner_engine import (
    COMMON_INDUSTRIAL_SUBNETS,
    DiscoveredDevice,
    DiscoveryEngine,
    NetworkAdapter,
    add_temporary_ip_alias,
    get_network_adapters,
    is_admin,
    scan_device_ports,
    send_arp_request,
)

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class FactoryReconApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()

        self.title("FactoryRecon — Escáner Ethernet y Descubrimiento de IP")
        self.geometry("1240x780")
        self.minsize(1020, 660)

        # Ensure RJ45 logo and window icon exist and apply them
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.logo_png_path = os.path.join(base_dir, "rj45_logo.png")
        self.logo_ico_path = os.path.join(base_dir, "rj45_icon.ico")
        if not (os.path.exists(self.logo_png_path) and os.path.exists(self.logo_ico_path)):
            try:
                generate_rj45_assets(base_dir)
            except Exception:
                pass
        try:
            if os.path.exists(self.logo_ico_path):
                self.iconbitmap(self.logo_ico_path)
        except Exception:
            pass

        self.engine = DiscoveryEngine(on_device_Callback=self._on_device_updated)
        self.adapters: list[NetworkAdapter] = []
        self.selected_adapter: Optional[NetworkAdapter] = None
        self.selected_device_ip: Optional[str] = None
        self.ui_dirty = False
        self.last_log_count = 0

        self._build_ui()
        self._refresh_adapters()

        # Start passive background listener automatically
        if self.selected_adapter:
            self.engine.start_passive_listeners(self.selected_adapter)

        # Trigger an initial quick ARP table read
        if self.selected_adapter:
            threading.Thread(
                target=self._initial_quick_check,
                args=(self.selected_adapter,),
                daemon=True,
            ).start()

        # Periodic UI sync loop
        self.after(250, self._periodic_ui_update)

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # ==================== TOP HEADER & ADAPTER BAR ====================
        header_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E2E8F0", "#161F30"))
        header_frame.grid(row=0, column=0, padx=14, pady=(12, 6), sticky="ew")
        header_frame.grid_columnconfigure(1, weight=1)

        # Title, RJ45 Logo & Admin Badge
        title_box = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_box.grid(row=0, column=0, padx=14, pady=10, sticky="w")

        if os.path.exists(self.logo_png_path):
            try:
                pil_logo = Image.open(self.logo_png_path)
                self.rj45_ctk_image = ctk.CTkImage(light_image=pil_logo, dark_image=pil_logo, size=(34, 34))
                logo_lbl = ctk.CTkLabel(title_box, text="", image=self.rj45_ctk_image)
                logo_lbl.pack(side="left", padx=(0, 8))
            except Exception:
                pass

        title_lbl = ctk.CTkLabel(
            title_box,
            text="FactoryRecon",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=("#1E3A8A", "#38BDF8"),
        )
        title_lbl.pack(side="left", padx=(0, 10))

        admin_status = is_admin()
        badge_text = "MODO ADMINISTRADOR (L2 Completo)" if admin_status else "MODO ESTÁNDAR (Sin Admin)"
        badge_color = "#059669" if admin_status else "#D97706"
        self.admin_badge = ctk.CTkLabel(
            title_box,
            text=f" {badge_text} ",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=badge_color,
             text_color="white",
            corner_radius=6,
        )
        self.admin_badge.pack(side="left", padx=4)

        if not admin_status:
            self.btn_elevate = ctk.CTkButton(
                title_box,
                text="Elevar a Admin",
                width=110,
                height=26,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#334155",
                hover_color="#475569",
                command=self._relaunch_as_admin,
            )
            self.btn_elevate.pack(side="left", padx=6)

        # Adapter Selector Controls
        adapter_box = ctk.CTkFrame(header_frame, fg_color="transparent")
        adapter_box.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        adapter_box.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            adapter_box,
            text="Adaptador Ethernet:",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).grid(row=0, column=0, padx=(6, 8), sticky="w")

        self.adapter_combo = ctk.CTkComboBox(
            adapter_box,
            values=["Cargando adaptadores..."],
            command=self._on_adapter_selected,
            height=32,
            font=ctk.CTkFont(size=13),
        )
        self.adapter_combo.grid(row=0, column=1, padx=4, sticky="ew")

        self.btn_refresh_adapters = ctk.CTkButton(
            adapter_box,
            text="↻ Actualizar Red",
            width=125,
            height=32,
            fg_color="#334155",
            hover_color="#475569",
            command=self._refresh_adapters,
        )
        self.btn_refresh_adapters.grid(row=0, column=2, padx=(6, 4))

        # ==================== CONTROL & SCAN BAR ====================
        ctrl_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=("#F1F5F9", "#1E293B"))
        ctrl_frame.grid(row=1, column=0, padx=14, pady=6, sticky="ew")
        ctrl_frame.grid_columnconfigure(3, weight=1)

        self.btn_scan = ctk.CTkButton(
            ctrl_frame,
            text="🔍 ESCANEAR EQUIPO CONECTADO",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=40,
            width=270,
            fg_color="#0284C7",
            hover_color="#0369A1",
            command=self._start_scan_clicked,
        )
        self.btn_scan.grid(row=0, column=0, padx=(14, 8), pady=10)

        self.btn_probe = ctk.CTkButton(
            ctrl_frame,
            text="📡 Sonda Broadcast Rápida",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=40,
            width=195,
            fg_color="#0D9488",
            hover_color="#0F766E",
            command=self._quick_broadcast_clicked,
        )
        self.btn_probe.grid(row=0, column=1, padx=6, pady=10)

        self.cross_subnet_var = ctk.BooleanVar(value=True)
        self.chk_cross_subnet = ctk.CTkCheckBox(
            ctrl_frame,
            text="Buscar en otras subredes\n(192.168.0/1/2/10/100, 10.0.0.x)",
            variable=self.cross_subnet_var,
            font=ctk.CTkFont(size=12),
        )
        self.chk_cross_subnet.grid(row=0, column=2, padx=12, pady=10)

        # Custom subnet input
        custom_box = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        custom_box.grid(row=0, column=3, padx=8, pady=10, sticky="ew")
        custom_box.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            custom_box,
            text="Rango extra (opcional):",
            font=ctk.CTkFont(size=12),
        ).grid(row=0, column=0, padx=(4, 6))

        self.entry_custom_subnet = ctk.CTkEntry(
            custom_box,
            placeholder_text="Ej: 192.168.5.0/24 o IP específica",
            height=34,
        )
        self.entry_custom_subnet.grid(row=0, column=1, padx=4, sticky="ew")

        self.btn_clear = ctk.CTkButton(
            ctrl_frame,
            text="🗑 Limpiar",
            width=90,
            height=34,
            fg_color="#475569",
            hover_color="#64748B",
            command=self._clear_devices,
        )
        self.btn_clear.grid(row=0, column=4, padx=(6, 14), pady=10)

        # Progress bar & status
        status_subframe = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        status_subframe.grid(row=1, column=0, columnspan=5, padx=14, pady=(0, 10), sticky="ew")
        status_subframe.grid_columnconfigure(1, weight=1)

        self.lbl_status = ctk.CTkLabel(
            status_subframe,
            text="Listo para escanear",
            font=ctk.CTkFont(size=12),
            text_color="#94A3B8",
        )
        self.lbl_status.grid(row=0, column=0, padx=(0, 12), sticky="w")

        self.progress_bar = ctk.CTkProgressBar(status_subframe, height=10)
        self.progress_bar.grid(row=0, column=1, sticky="ew")
        self.progress_bar.set(0.0)

        self.lbl_count = ctk.CTkLabel(
            status_subframe,
            text="0 Equipos encontrados",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#38BDF8",
        )
        self.lbl_count.grid(row=0, column=2, padx=(12, 0), sticky="e")

        # ==================== MAIN SPLIT VIEW (DEVICES LIST + INSPECTOR) ====================
        main_pane = ctk.CTkFrame(self, fg_color="transparent")
        main_pane.grid(row=2, column=0, padx=14, pady=(2, 6), sticky="nsew")
        main_pane.grid_columnconfigure(0, weight=3)
        main_pane.grid_columnconfigure(1, weight=2)
        main_pane.grid_rowconfigure(0, weight=1)

        # Left: Discovered Devices Scrollable Table
        left_card = ctk.CTkFrame(main_pane, corner_radius=10, fg_color=("#F8FAFC", "#0F172A"))
        left_card.grid(row=0, column=0, padx=(0, 8), sticky="nsew")
        left_card.grid_columnconfigure(0, weight=1)
        left_card.grid_rowconfigure(1, weight=1)

        table_header = ctk.CTkFrame(left_card, height=36, corner_radius=6, fg_color="#1E293B")
        table_header.grid(row=0, column=0, padx=10, pady=(10, 4), sticky="ew")
        table_header.grid_columnconfigure(0, minsize=135)
        table_header.grid_columnconfigure(1, minsize=145)
        table_header.grid_columnconfigure(2, weight=1)
        table_header.grid_columnconfigure(3, minsize=140)

        headers = [
            (0, "DIRECCIÓN IP"),
            (1, "DIRECCIÓN MAC"),
            (2, "FABRICANTE / NOMBRE"),
            (3, "ESTADO SUBRED / VÍA"),
        ]
        for col_idx, text in headers:
            ctk.CTkLabel(
                table_header,
                text=text,
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color="#94A3B8",
            ).grid(row=0, column=col_idx, padx=8, pady=6, sticky="w")

        self.devices_scroll = ctk.CTkScrollableFrame(
            left_card,
            fg_color="transparent",
        )
        self.devices_scroll.grid(row=1, column=0, padx=6, pady=(0, 8), sticky="nsew")
        self.devices_scroll.grid_columnconfigure(0, weight=1)

        # Right: Device Detail & Inspector Panel
        right_card = ctk.CTkFrame(main_pane, corner_radius=10, fg_color=("#F8FAFC", "#161F30"))
        right_card.grid(row=0, column=1, padx=(4, 0), sticky="nsew")
        right_card.grid_columnconfigure(0, weight=1)
        right_card.grid_rowconfigure(2, weight=1)

        inspector_title = ctk.CTkLabel(
            right_card,
            text="🔎 Inspector de Equipo y Puertos",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color="#38BDF8",
        )
        inspector_title.grid(row=0, column=0, padx=14, pady=(12, 6), sticky="w")

        # Quick Action Buttons for Selected Device
        action_bar = ctk.CTkFrame(right_card, fg_color="transparent")
        action_bar.grid(row=1, column=0, padx=12, pady=4, sticky="ew")

        self.btn_copy_ip = ctk.CTkButton(
            action_bar,
            text="📋 Copiar IP",
            width=95,
            height=30,
            fg_color="#334155",
            hover_color="#475569",
            command=self._copy_selected_ip,
        )
        self.btn_copy_ip.pack(side="left", padx=3)

        self.btn_open_web = ctk.CTkButton(
            action_bar,
            text="🌐 Abrir Web",
            width=95,
            height=30,
            fg_color="#334155",
            hover_color="#475569",
            command=self._open_selected_web,
        )
        self.btn_open_web.pack(side="left", padx=3)

        self.btn_deep_ports = ctk.CTkButton(
            action_bar,
            text="⚡ Escaneo Puertos",
            width=125,
            height=30,
            fg_color="#0284C7",
            hover_color="#0369A1",
            command=self._deep_port_scan_selected,
        )
        self.btn_deep_ports.pack(side="left", padx=3)

        self.btn_match_subnet = ctk.CTkButton(
            action_bar,
            text="🔗 Igualar Subred PC",
            width=135,
            height=30,
            fg_color="#7C3AED",
            hover_color="#6D28D9",
            command=self._add_ip_alias_for_selected,
        )
        self.btn_match_subnet.pack(side="left", padx=3)

        self.inspector_text = ctk.CTkTextbox(
            right_card,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#0B1120",
            text_color="#E2E8F0",
            wrap="word",
        )
        self.inspector_text.grid(row=2, column=0, padx=12, pady=(6, 12), sticky="nsew")
        self._set_inspector_content(
            "Selecciona un equipo de la lista izquierda para inspeccionar:\n\n"
            "• Dirección IPv4 y Dirección Física (MAC)\n"
            "• Fabricante del hardware (OUI: Siemens, Allen-Bradley, Hikvision, Cisco, etc.)\n"
            "• Diagnóstico de Subred (detecta si el equipo está en un segmento IP distinto al de tu PC)\n"
            "• Puertos TCP abiertos (HTTP, SSH, Modbus 502, Siemens S7 102, EtherNet/IP 44818, RTSP 554...)\n"
            "• Botón 'Igualar Subred PC' para agregar automáticamente una IP secundaria en Windows y conectarte al equipo sin perder tu configuración."
        )

        # ==================== BOTTOM LOG CONSOLE ====================
        log_frame = ctk.CTkFrame(self, height=135, corner_radius=10, fg_color="#0B1120")
        log_frame.grid(row=3, column=0, padx=14, pady=(4, 12), sticky="ew")
        log_frame.grid_columnconfigure(0, weight=1)

        log_hdr = ctk.CTkLabel(
            log_frame,
            text="REGISTRO DE ACTIVIDAD EN TIEMPO REAL (ARP / mDNS / SSDP / SONDA CAPA 2)",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#64748B",
        )
        log_hdr.grid(row=0, column=0, padx=12, pady=(6, 2), sticky="w")

        self.log_box = ctk.CTkTextbox(
            log_frame,
            height=95,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color="#0B1120",
            text_color="#38BDF8",
        )
        self.log_box.grid(row=1, column=0, padx=10, pady=(0, 8), sticky="ew")

    # ==================== ADAPTER & SCAN LOGIC ====================

    def _refresh_adapters(self) -> None:
        self.adapters = get_network_adapters()
        if not self.adapters:
            self.adapter_combo.configure(values=["No se detectaron adaptadores Ethernet"])
            self.selected_adapter = None
            return

        values = []
        for a in self.adapters:
            ip_disp = a.primary_ip
            apipa_tag = " [APIPA / Sin DHCP]" if a.is_apipa else f"/{a.primary_prefix}"
            status_tag = "🟢" if a.status.lower() == "up" else "⚪"
            label = f"{status_tag} {a.name} — {ip_disp}{apipa_tag} ({a.description})"
            values.append(label)

        self.adapter_combo.configure(values=values)
        self.adapter_combo.set(values[0])
        self.selected_adapter = self.adapters[0]
        self.engine.log(
            f"Adaptador seleccionado: {self.selected_adapter.name} ({self.selected_adapter.description}) "
            f"- IP: {self.selected_adapter.primary_ip} - MAC: {self.selected_adapter.mac_address}"
        )

    def _on_adapter_selected(self, choice: str) -> None:
        idx = self.adapter_combo.cget("values").index(choice)
        if 0 <= idx < len(self.adapters):
            self.selected_adapter = self.adapters[idx]
            self.engine.log(
                f"Cambiado a adaptador: {self.selected_adapter.name} (IP: {self.selected_adapter.primary_ip})"
            )
            threading.Thread(
                target=self._initial_quick_check,
                args=(self.selected_adapter,),
                daemon=True,
            ).start()

    def _initial_quick_check(self, adapter: NetworkAdapter) -> None:
        from scanner_engine import get_kernel_arp_table

        for ip_str, mac_str, _ in get_kernel_arp_table(adapter.if_index):
            self.engine.register_device(ip=ip_str, mac=mac_str, method="Tabla ARP", adapter=adapter)

    def _on_device_updated(self, device: DiscoveredDevice) -> None:
        self.ui_dirty = True

    def _start_scan_clicked(self) -> None:
        if not self.selected_adapter:
            messagebox.showwarning("Sin adaptador", "Selecciona un adaptador Ethernet primero.")
            return
        if self.engine.scan_in_progress:
            return

        custom_txt = self.entry_custom_subnet.get().strip()
        custom_subnets: Optional[list[str]] = None
        if custom_txt:
            if "/" not in custom_txt and custom_txt.count(".") == 3:
                # Single IP or base: convert to /24
                parts = custom_txt.split(".")
                custom_subnets = [f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"]
            else:
                custom_subnets = [s.strip() for s in custom_txt.split(",") if s.strip()]

        deep = self.cross_subnet_var.get()
        self.btn_scan.configure(state="disabled", text="⏳ ESCANEANDO RED...")
        threading.Thread(
            target=self._run_scan_worker,
            args=(self.selected_adapter, custom_subnets, deep),
            daemon=True,
        ).start()

    def _run_scan_worker(
        self,
        adapter: NetworkAdapter,
        custom_subnets: Optional[list[str]],
        deep: bool,
    ) -> None:
        try:
            self.engine.run_full_scan(adapter, custom_subnets=custom_subnets, deep_cross_subnet=deep)
        finally:
            self.ui_dirty = True
            self.after(0, lambda: self.btn_scan.configure(state="normal", text="🔍 ESCANEAR EQUIPO CONECTADO"))

    def _quick_broadcast_clicked(self) -> None:
        if not self.selected_adapter:
            return
        threading.Thread(
            target=self.engine.send_active_broadcast_probes,
            args=(self.selected_adapter,),
            daemon=True,
        ).start()

    def _clear_devices(self) -> None:
        with self.engine.lock:
            self.engine.devices.clear()
        self.selected_device_ip = None
        self.ui_dirty = True
        self._set_inspector_content("Lista limpiada. Haz clic en 'Escanear Equipo Conectado' para iniciar un nuevo descubrimiento.")

    # ==================== PERIODIC UI REFRESH ====================

    def _periodic_ui_update(self) -> None:
        # Update progress and status text
        self.progress_bar.set(self.engine.scan_progress)
        self.lbl_status.configure(text=self.engine.scan_status_text)

        # Update logs if new entries arrived
        with self.engine.lock:
            current_log_len = len(self.engine.logs)
            if current_log_len != self.last_log_count:
                log_text = "\n".join(self.engine.logs[-80:])
                self.last_log_count = current_log_len
            else:
                log_text = None

        if log_text is not None:
            self.log_box.configure(state="normal")
            self.log_box.delete("1.0", "end")
            self.log_box.insert("end", log_text)
            self.log_box.see("end")
            self.log_box.configure(state="disabled")

        if self.ui_dirty:
            self.ui_dirty = False
            self._rebuild_device_rows()
            if self.selected_device_ip:
                self._update_inspector_for_ip(self.selected_device_ip)

        self.after(300, self._periodic_ui_update)

    def _rebuild_device_rows(self) -> None:
        for child in self.devices_scroll.winfo_children():
            child.destroy()

        with self.engine.lock:
            devices_list = list(self.engine.devices.values())

        # Sort by IP numerically
        def ip_key(d: DiscoveredDevice) -> tuple:
            try:
                return tuple(int(x) for x in d.ip.split("."))
            except Exception:
                return (999, 999, 999, 999)

        devices_list.sort(key=ip_key)
        count = len(devices_list)
        self.lbl_count.configure(text=f"{count} Equipo{'s' if count != 1 else ''} encontrado{'s' if count != 1 else ''}")

        if not devices_list:
            empty_lbl = ctk.CTkLabel(
                self.devices_scroll,
                text="Ningún equipo detectado aún.\nConecta el cable Ethernet y presiona 'ESCANEAR EQUIPO CONECTADO'.",
                font=ctk.CTkFont(size=13),
                text_color="#64748B",
            )
            empty_lbl.grid(row=0, column=0, pady=40)
            return

        # Auto-select first device if none selected
        if not self.selected_device_ip and devices_list:
            self.selected_device_ip = devices_list[0].ip

        for row_idx, dev in enumerate(devices_list):
            is_selected = dev.ip == self.selected_device_ip
            bg_color = "#1E3A8A" if is_selected else ("#E2E8F0", "#1E293B")
            border_col = "#38BDF8" if is_selected else "#334155"

            row_card = ctk.CTkFrame(
                self.devices_scroll,
                corner_radius=8,
                fg_color=bg_color,
                border_width=2 if is_selected else 1,
                border_color=border_col,
            )
            row_card.grid(row=row_idx, column=0, padx=4, pady=4, sticky="ew")
            row_card.grid_columnconfigure(0, minsize=135)
            row_card.grid_columnconfigure(1, minsize=145)
            row_card.grid_columnconfigure(2, weight=1)
            row_card.grid_columnconfigure(3, minsize=140)

            # IP Label
            ip_lbl = ctk.CTkLabel(
                row_card,
                text=f"🟢 {dev.ip}",
                font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
                text_color="#38BDF8" if not is_selected else "#FFFFFF",
            )
            ip_lbl.grid(row=0, column=0, padx=10, pady=8, sticky="w")

            # MAC Label
            mac_lbl = ctk.CTkLabel(
                row_card,
                text=dev.mac,
                font=ctk.CTkFont(family="Consolas", size=12),
                text_color="#CBD5E1",
            )
            mac_lbl.grid(row=0, column=1, padx=8, pady=8, sticky="w")

            # Vendor + Hostname + Ports summary
            vendor_str = dev.vendor
            if dev.hostname:
                vendor_str = f"{dev.hostname} ({dev.vendor})"
            if dev.open_ports:
                ports_preview = ", ".join(str(p) for p in sorted(dev.open_ports.keys())[:5])
                vendor_str += f"  [Puertos: {ports_preview}]"

            vendor_lbl = ctk.CTkLabel(
                row_card,
                text=vendor_str,
                font=ctk.CTkFont(size=12, weight="bold" if dev.hostname else "normal"),
                text_color="#F8FAFC",
                anchor="w",
            )
            vendor_lbl.grid(row=0, column=2, padx=8, pady=8, sticky="ew")

            # Subnet status badge
            if dev.subnet_mismatch:
                status_txt = "⚠️ OTRA SUBRED"
                status_col = "#F59E0B"
            else:
                methods_short = "/".join(sorted(dev.discovery_methods))[:18]
                status_txt = f"✓ Misma Red ({methods_short})"
                status_col = "#10B981"

            status_lbl = ctk.CTkLabel(
                row_card,
                text=status_txt,
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=status_col,
            )
            status_lbl.grid(row=0, column=3, padx=10, pady=8, sticky="e")

            # Bind click event to select device
            for widget in (row_card, ip_lbl, mac_lbl, vendor_lbl, status_lbl):
                widget.bind("<Button-1>", lambda e, ip=dev.ip: self._select_device(ip))

    def _select_device(self, ip: str) -> None:
        self.selected_device_ip = ip
        self._rebuild_device_rows()
        self._update_inspector_for_ip(ip)

    def _update_inspector_for_ip(self, ip: str) -> None:
        with self.engine.lock:
            dev = self.engine.devices.get(ip)
        if not dev:
            return

        adapter_info = (
            f"{self.selected_adapter.name} ({self.selected_adapter.primary_ip}/{self.selected_adapter.primary_prefix})"
            if self.selected_adapter
            else "N/A"
        )

        lines = [
            f"==================================================",
            f" REPORTE DE EQUIPO DETECTADO: {dev.ip}",
            f"==================================================",
            f"• Dirección IPv4    : {dev.ip}",
            f"• Dirección MAC     : {dev.mac}",
            f"• Fabricante (OUI)  : {dev.vendor}",
            f"• Hostname / NetBIOS: {dev.hostname or 'No reportado'}",
            f"• Métodos Detección : {', '.join(sorted(dev.discovery_methods))}",
            f"• Adaptador Local   : {adapter_info}",
            f"• Primera / Última  : {time.strftime('%H:%M:%S', time.localtime(dev.first_seen))} / {time.strftime('%H:%M:%S', time.localtime(dev.last_seen))}",
        ]

        if dev.extra_info:
            lines.append(f"• Info de Servicio  : {dev.extra_info}")

        lines.append("")
        if dev.subnet_mismatch:
            lines.extend(
                [
                    "⚠️ [ALERTA DE SUBRED DIFERENTE]",
                    f"El equipo ({dev.ip}) está en un segmento de red distinto al de tu PC ({adapter_info}).",
                    "👉 SOLUCIÓN RÁPIDA: Presiona el botón morado '🔗 Igualar Subred PC' arriba para agregar automáticamente una IP compatible en Windows y poder conectarte.",
                    "",
                ]
            )
        else:
            lines.append("✅ [SUBRED COMPATIBLE] Tu PC puede comunicarse directamente con esta IP.")
            lines.append("")

        lines.append("--------------------------------------------------")
        lines.append(" PUERTOS TCP ABIERTOS Y SERVICIOS")
        lines.append("--------------------------------------------------")
        if dev.open_ports:
            for port, srv in sorted(dev.open_ports.items()):
                lines.append(f"  [ABIERTO] TCP/{port:<5}  --->  {srv}")
        else:
            lines.append("  Ningún puerto común detectado aún (o firewall activo).")
            lines.append("  Presiona '⚡ Escaneo Puertos' para un análisis profundo.")

        self._set_inspector_content("\n".join(lines))

    def _set_inspector_content(self, text: str) -> None:
        self.inspector_text.configure(state="normal")
        self.inspector_text.delete("1.0", "end")
        self.inspector_text.insert("end", text)
        self.inspector_text.configure(state="disabled")

    # ==================== DEVICE ACTIONS ====================

    def _copy_selected_ip(self) -> None:
        if not self.selected_device_ip:
            return
        self.clipboard_clear()
        self.clipboard_append(self.selected_device_ip)
        self.engine.log(f"IP {self.selected_device_ip} copiada al portapapeles.")

    def _open_selected_web(self) -> None:
        if not self.selected_device_ip:
            return
        with self.engine.lock:
            dev = self.engine.devices.get(self.selected_device_ip)
        proto = "https" if (dev and 443 in dev.open_ports and 80 not in dev.open_ports) else "http"
        url = f"{proto}://{self.selected_device_ip}"
        self.engine.log(f"Abriendo navegador en {url}...")
        webbrowser.open(url)

    def _deep_port_scan_selected(self) -> None:
        if not self.selected_device_ip:
            return
        target_ip = self.selected_device_ip
        self.engine.log(f"Iniciando escaneo profundo de puertos TCP en {target_ip}...")

        def worker() -> None:
            # Extended industrial + IT port list
            extended_ports = [
                20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 81, 88, 102, 110, 111, 123,
                135, 137, 139, 143, 161, 162, 389, 443, 445, 502, 515, 554, 631,
                789, 1080, 1089, 1090, 1091, 1433, 1521, 1883, 1911, 1962, 2222,
                2404, 3000, 3306, 3389, 4000, 4840, 4911, 5000, 5001, 5007, 5094,
                5432, 5900, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9100,
                9600, 10000, 18245, 20000, 34962, 34963, 34964, 44818, 47808, 48898,
            ]
            ports_found, banner = scan_device_ports(target_ip, ports=extended_ports, timeout=0.45)
            with self.engine.lock:
                dev = self.engine.devices.get(target_ip)
                if dev:
                    dev.open_ports.update(ports_found)
                    if banner and banner not in dev.extra_info:
                        dev.extra_info = f"{dev.extra_info} | {banner}".strip(" |")
            self.engine.log(
                f"Escaneo de puertos en {target_ip} completado: {len(ports_found)} puertos abiertos."
            )
            self.ui_dirty = True

        threading.Thread(target=worker, daemon=True).start()

    def _add_ip_alias_for_selected(self) -> None:
        if not self.selected_device_ip or not self.selected_adapter:
            return
        ok, msg = add_temporary_ip_alias(self.selected_adapter.if_index, self.selected_device_ip)
        self.engine.log(msg)
        if ok:
            self._refresh_adapters()
            messagebox.showinfo("Subred Igualada", msg)
        else:
            messagebox.showwarning("Permisos de Administrador Requeridos", msg)

    def _relaunch_as_admin(self) -> None:
        """Re-launches the application with Windows UAC Administrator elevation."""
        try:
            script = sys.argv[0]
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, f'"{script}"', None, 1
            )
            self.destroy()
        except Exception as exc:
            messagebox.showerror("Error", f"No se pudo elevar permisos: {exc}")


if __name__ == "__main__":
    app = FactoryReconApp()
    app.mainloop()

