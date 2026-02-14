"""Hyperreal Memory Forensics — Negative Space Analysis.

Analyzes what's *missing* from memory rather than what's present.
Inspired by Baudrillard's concept that hyperreality is defined
by the absence it conceals.
"""

import os
import struct
import json
from datetime import datetime
from collections import Counter


class NegativeSpaceAnalyzer:
    """Detect what's been erased, hidden, or hollowed out in memory."""

    # ELF magic bytes
    ELF_MAGIC = b"\x7fELF"

    # Known memory region patterns that indicate hiding
    HOLLOW_PATTERNS = {
        b"\x00" * 4096: "Zero Page — potential evidence wipe",
        b"\xcc" * 64: "INT3 sled — debugger trap or code cave",
        b"\x90" * 64: "NOP sled — potential shellcode runway",
        b"\xfe\xed\xfa\xce": "Mach-O magic — cross-platform artifact",
    }

    def analyze_memory_dump(self, filepath):
        """Analyze a memory dump file for negative space indicators."""
        if not os.path.exists(filepath):
            return {"error": f"File not found: {filepath}"}

        file_size = os.path.getsize(filepath)
        results = {
            "file": filepath,
            "size": file_size,
            "scan_time": datetime.utcnow().isoformat(),
            "negative_spaces": [],
            "entropy_map": [],
            "hidden_structures": [],
        }

        with open(filepath, "rb") as f:
            offset = 0
            block_size = 4096
            zero_runs = 0
            total_blocks = 0

            while True:
                block = f.read(block_size)
                if not block:
                    break
                total_blocks += 1

                # Detect zero regions (negative space)
                if block == b"\x00" * len(block):
                    zero_runs += 1
                    if zero_runs == 1:
                        zero_start = offset
                else:
                    if zero_runs > 0:
                        results["negative_spaces"].append({
                            "type": "void",
                            "start": hex(zero_start),
                            "end": hex(offset),
                            "size": zero_runs * block_size,
                            "interpretation": "Evidence of erasure — the absence is the message",
                        })
                        zero_runs = 0

                # Check for hollow patterns
                for pattern, meaning in self.HOLLOW_PATTERNS.items():
                    if pattern in block:
                        pos = block.find(pattern)
                        results["hidden_structures"].append({
                            "offset": hex(offset + pos),
                            "pattern": meaning,
                            "order": 3,  # Masks absence of reality
                        })

                # Entropy calculation per block
                byte_counts = Counter(block)
                entropy = 0.0
                for count in byte_counts.values():
                    if count > 0:
                        p = count / len(block)
                        import math
                        entropy -= p * math.log2(p)

                if total_blocks % 256 == 0:  # Sample every 1MB
                    results["entropy_map"].append({
                        "offset": hex(offset),
                        "entropy": round(entropy, 3),
                        "classification": self._classify_entropy(entropy),
                    })

                offset += len(block)

            # Handle trailing zeros
            if zero_runs > 0:
                results["negative_spaces"].append({
                    "type": "void",
                    "start": hex(zero_start),
                    "end": hex(offset),
                    "size": zero_runs * block_size,
                    "interpretation": "Terminal void — absence at the boundary",
                })

        results["summary"] = {
            "total_blocks": total_blocks,
            "void_percentage": round(
                sum(ns["size"] for ns in results["negative_spaces"]) / max(file_size, 1) * 100, 2
            ),
            "hidden_structures_count": len(results["hidden_structures"]),
            "hyperreality_assessment": self._assess_hyperreality(results),
        }

        return results

    def _classify_entropy(self, entropy):
        """Classify entropy level."""
        if entropy < 1.0:
            return "VOID — near-zero information content"
        elif entropy < 4.0:
            return "STRUCTURED — organized data (text, code)"
        elif entropy < 7.0:
            return "COMPLEX — rich data (compressed, encrypted)"
        else:
            return "MAXIMUM — encrypted or random (concealment?)"

    def _assess_hyperreality(self, results):
        """Assess the hyperreality level of the memory space."""
        void_pct = results["summary"]["void_percentage"] if "summary" in results else 0
        hidden = len(results["hidden_structures"])

        if void_pct > 50 and hidden > 5:
            return {
                "level": "HYPERREAL",
                "order": 4,
                "analysis": "Memory space is more absence than presence — "
                           "the simulation has consumed the real",
            }
        elif void_pct > 20 or hidden > 2:
            return {
                "level": "SIMULATION",
                "order": 3,
                "analysis": "Significant voids mask the absence of original data",
            }
        elif hidden > 0:
            return {
                "level": "REPRESENTATION",
                "order": 2,
                "analysis": "Some signs of manipulation — reality is being mediated",
            }
        else:
            return {
                "level": "REAL",
                "order": 1,
                "analysis": "Memory appears authentic — faithful representation",
            }


class ProcessMemoryForensics:
    """Analyze live process memory for hyperreal indicators."""

    def read_proc_maps(self, pid):
        """Read and analyze process memory maps from /proc."""
        maps_file = f"/proc/{pid}/maps"
        if not os.path.exists(maps_file):
            return {"error": f"Process {pid} not found or not accessible"}

        regions = []
        try:
            with open(maps_file, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 5:
                        addr_range = parts[0]
                        perms = parts[1]
                        offset = parts[2]
                        dev = parts[3]
                        inode = parts[4]
                        pathname = parts[5] if len(parts) > 5 else "[anonymous]"

                        start, end = addr_range.split("-")
                        size = int(end, 16) - int(start, 16)

                        region = {
                            "start": f"0x{start}",
                            "end": f"0x{end}",
                            "size": size,
                            "permissions": perms,
                            "offset": offset,
                            "pathname": pathname,
                        }

                        # Classify region
                        region["simulacra_analysis"] = self._classify_region(
                            perms, pathname, size
                        )
                        regions.append(region)
        except PermissionError:
            return {"error": "Permission denied — run as root"}

        return {
            "pid": pid,
            "scan_time": datetime.utcnow().isoformat(),
            "total_regions": len(regions),
            "total_mapped": sum(r["size"] for r in regions),
            "suspicious": [r for r in regions if r["simulacra_analysis"]["order"] >= 3],
            "regions": regions,
        }

    def _classify_region(self, perms, pathname, size):
        """Classify a memory region by simulacra order."""
        # RWX regions are suspicious (Order 3 — shouldn't exist in normal operation)
        if "rwx" in perms:
            return {
                "order": 3,
                "classification": "Executable Writable Region",
                "description": "RWX permissions mask the absence of proper memory protection",
                "threat": "HIGH",
            }

        # Anonymous executable regions (Order 2 — code without a source)
        if "x" in perms and pathname == "[anonymous]":
            return {
                "order": 2,
                "classification": "Anonymous Code",
                "description": "Executable code with no file backing — perverted copy without original",
                "threat": "MEDIUM",
            }

        # Deleted file mappings (Order 3 — phantom references)
        if "(deleted)" in pathname:
            return {
                "order": 3,
                "classification": "Phantom Mapping",
                "description": "Maps a deleted file — references an absence",
                "threat": "MEDIUM",
            }

        # Stack/heap (Order 1 — authentic)
        if pathname in ("[stack]", "[heap]"):
            return {
                "order": 1,
                "classification": "Authentic Region",
                "description": "Standard process memory — faithful to system reality",
                "threat": "NONE",
            }

        # Normal file-backed (Order 1)
        return {
            "order": 1,
            "classification": "File-Backed Region",
            "description": "Memory faithfully represents file content",
            "threat": "NONE",
        }

    def detect_process_hollowing(self, pid):
        """Detect process hollowing — a quintessential simulacra attack.

        In process hollowing, a legitimate process is gutted and replaced
        with malicious code while maintaining its external identity.
        This is Baudrillard's Order 3: the process masks the absence
        of its original content.
        """
        result = {
            "pid": pid,
            "scan_time": datetime.utcnow().isoformat(),
            "indicators": [],
        }

        # Check if exe link matches expected binary
        try:
            exe_path = os.readlink(f"/proc/{pid}/exe")
            with open(f"/proc/{pid}/cmdline", "r") as f:
                cmdline = f.read().replace("\x00", " ").strip()

            # Binary name mismatch
            exe_name = os.path.basename(exe_path)
            cmd_name = cmdline.split()[0] if cmdline else ""
            if cmd_name and os.path.basename(cmd_name) != exe_name:
                result["indicators"].append({
                    "type": "NAME_MISMATCH",
                    "detail": f"exe={exe_name} but cmdline claims {cmd_name}",
                    "order": 2,
                })

            # Check for deleted binary
            if "(deleted)" in exe_path:
                result["indicators"].append({
                    "type": "DELETED_BINARY",
                    "detail": "Running from deleted executable — phantom process",
                    "order": 3,
                })

        except (OSError, PermissionError, IndexError):
            result["indicators"].append({
                "type": "INACCESSIBLE",
                "detail": "Cannot read process details — potential concealment",
                "order": 2,
            })

        if result["indicators"]:
            max_order = max(i["order"] for i in result["indicators"])
            result["assessment"] = {
                "hollowed": max_order >= 3,
                "order": max_order,
                "conclusion": (
                    "Process appears hollowed — a simulacrum wearing the skin of legitimacy"
                    if max_order >= 3
                    else "Suspicious indicators found — further analysis recommended"
                ),
            }
        else:
            result["assessment"] = {
                "hollowed": False,
                "order": 1,
                "conclusion": "Process appears authentic — no hollowing indicators",
            }

        return result
