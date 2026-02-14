"""Hyperreal Filesystem Forensics — Detecting the absence of the real.

Examines filesystems through Baudrillard's hyperreality framework:
what has been deleted, overwritten, or hollowed out reveals more
than what remains.
"""

import os
import stat
import hashlib
import json
from datetime import datetime
from collections import defaultdict


class FilesystemHyperreal:
    """Analyze filesystem for hyperreal indicators — what's missing matters most."""

    # Temporal anomaly thresholds
    FUTURE_THRESHOLD = 3600  # 1 hour in the future
    ANCIENT_THRESHOLD = 946684800  # Before Y2K

    def scan_temporal_anomalies(self, root_path, max_depth=3):
        """Find files with impossible or suspicious timestamps.

        In hyperreality, time itself becomes simulated — timestamps
        that don't match reality indicate manipulation.
        """
        now = datetime.now().timestamp()
        anomalies = []

        for dirpath, dirnames, filenames in os.walk(root_path):
            # Depth control
            depth = dirpath.replace(root_path, "").count(os.sep)
            if depth >= max_depth:
                dirnames.clear()
                continue

            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                try:
                    st = os.lstat(fpath)

                    # Future timestamps (Order 4 — no relation to temporal reality)
                    if st.st_mtime > now + self.FUTURE_THRESHOLD:
                        anomalies.append({
                            "path": fpath,
                            "type": "FUTURE_TIMESTAMP",
                            "order": 4,
                            "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(),
                            "description": "File claims to be from the future — temporal simulacrum",
                        })

                    # Ancient timestamps (Order 3 — masks real creation time)
                    elif st.st_mtime < self.ANCIENT_THRESHOLD:
                        anomalies.append({
                            "path": fpath,
                            "type": "ANCIENT_TIMESTAMP",
                            "order": 3,
                            "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(),
                            "description": "Impossibly old timestamp — hiding true origin",
                        })

                    # mtime before ctime (Order 2 — contradictory metadata)
                    elif st.st_mtime < st.st_ctime - 60:
                        anomalies.append({
                            "path": fpath,
                            "type": "TEMPORAL_PARADOX",
                            "order": 2,
                            "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(),
                            "ctime": datetime.fromtimestamp(st.st_ctime).isoformat(),
                            "description": "Modified before created — timestomping detected",
                        })

                except (OSError, PermissionError):
                    continue

        return {
            "root": root_path,
            "scan_time": datetime.utcnow().isoformat(),
            "anomalies_found": len(anomalies),
            "anomalies": anomalies,
        }

    def detect_hidden_spaces(self, root_path, max_depth=3):
        """Find hidden files, alternate data streams, and concealed spaces."""
        hidden = []

        for dirpath, dirnames, filenames in os.walk(root_path):
            depth = dirpath.replace(root_path, "").count(os.sep)
            if depth >= max_depth:
                dirnames.clear()
                continue

            for fname in filenames:
                fpath = os.path.join(dirpath, fname)

                # Hidden files (dot-prefix)
                if fname.startswith(".") and fname not in (".gitignore", ".gitkeep", ".editorconfig"):
                    try:
                        st = os.stat(fpath)
                        hidden.append({
                            "path": fpath,
                            "type": "HIDDEN_FILE",
                            "size": st.st_size,
                            "order": 2,
                            "description": "File concealed by naming convention",
                        })
                    except (OSError, PermissionError):
                        continue

                # Files with no extension in binary directories
                try:
                    st = os.stat(fpath)
                    if "." not in fname and st.st_mode & stat.S_IXUSR:
                        hidden.append({
                            "path": fpath,
                            "type": "UNNAMED_EXECUTABLE",
                            "size": st.st_size,
                            "order": 2,
                            "description": "Executable without extension — identity obscured",
                        })
                except (OSError, PermissionError):
                    continue

            # Hidden directories
            for dname in dirnames:
                if dname.startswith(".") and dname not in (".git", ".github", ".vscode"):
                    hidden.append({
                        "path": os.path.join(dirpath, dname),
                        "type": "HIDDEN_DIRECTORY",
                        "order": 2,
                        "description": "Directory concealed by naming convention",
                    })

        return {
            "root": root_path,
            "scan_time": datetime.utcnow().isoformat(),
            "hidden_count": len(hidden),
            "items": hidden,
        }

    def find_duplicate_simulacra(self, root_path, max_depth=3):
        """Find duplicate files — copies that may have replaced originals.

        In Baudrillard's framework, when copies proliferate, the concept
        of 'original' becomes meaningless.
        """
        hash_map = defaultdict(list)

        for dirpath, dirnames, filenames in os.walk(root_path):
            depth = dirpath.replace(root_path, "").count(os.sep)
            if depth >= max_depth:
                dirnames.clear()
                continue

            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                try:
                    st = os.stat(fpath)
                    if st.st_size == 0 or st.st_size > 100 * 1024 * 1024:  # Skip empty/huge
                        continue
                    with open(fpath, "rb") as f:
                        h = hashlib.sha256(f.read()).hexdigest()
                    hash_map[h].append({
                        "path": fpath,
                        "size": st.st_size,
                        "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(),
                    })
                except (OSError, PermissionError):
                    continue

        duplicates = []
        for h, files in hash_map.items():
            if len(files) > 1:
                # The oldest file is the "original" (Order 1)
                files.sort(key=lambda x: x["mtime"])
                duplicates.append({
                    "hash": h,
                    "count": len(files),
                    "original": files[0],
                    "copies": files[1:],
                    "order": 2 if len(files) <= 3 else 3,
                    "analysis": (
                        "Multiple copies — the original loses primacy"
                        if len(files) <= 3
                        else "Proliferation of copies — original concept dissolves"
                    ),
                })

        return {
            "root": root_path,
            "scan_time": datetime.utcnow().isoformat(),
            "duplicate_groups": len(duplicates),
            "total_copies": sum(d["count"] - 1 for d in duplicates),
            "wasted_space": sum(
                sum(c["size"] for c in d["copies"]) for d in duplicates
            ),
            "duplicates": duplicates,
        }
