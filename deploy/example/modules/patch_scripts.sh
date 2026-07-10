#!/usr/bin/env bash
# Patch Scripts Module
# Applies manual patches to installed packages after venv setup

#############################################################################
# Apply Google Workspace MCP Async Fixes (by copying pre-patched files)
#############################################################################
patch_google_workspace() {
  local VENV_DIR="${1}"
  local PROJECT_PATH="${2}"
  
  echo "🔧 ==================================================="
  echo "🔧 APPLYING GOOGLE WORKSPACE MCP ASYNC PATCHES"
  echo "🔧 ==================================================="
  
  # Validate parameters
  if [[ -z "${VENV_DIR}" || -z "${PROJECT_PATH}" ]]; then
    echo "❌ Error: Missing required parameters for Google Workspace patching"
    echo "   VENV_DIR=${VENV_DIR}, PROJECT_PATH=${PROJECT_PATH}"
    return 1
  fi
  
  # Detect Python version in venv
  local PYTHON_VERSION=$(${PROJECT_PATH}/${VENV_DIR}/bin/python -c "import sys; print(f'python{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
  
  if [[ -z "${PYTHON_VERSION}" ]]; then
    echo "❌ Error: Could not detect Python version in venv"
    return 1
  fi
  
  echo "  • Detected Python version: ${PYTHON_VERSION}"
  
  local MCP_SUITE_PATH="${PROJECT_PATH}/${VENV_DIR}/lib/${PYTHON_VERSION}/site-packages/mcp_google_suite"
  local PATCHES_SOURCE="${PROJECT_PATH}/deploy/patches/mcp_google_suite"
  
  # Check if mcp-google-suite is installed
  if [[ ! -d "${MCP_SUITE_PATH}" ]]; then
    echo "⚠️  mcp-google-suite not found at ${MCP_SUITE_PATH}"
    echo "  • Skipping Google Workspace patches (package not installed)"
    return 0
  fi
  
  echo "  • Found mcp-google-suite at: ${MCP_SUITE_PATH}"
  
  # Check version (patches are for 0.1.1)
  local INSTALLED_VERSION=$(${PROJECT_PATH}/${VENV_DIR}/bin/pip show mcp-google-suite 2>/dev/null | grep "^Version:" | awk '{print $2}')
  if [[ -n "${INSTALLED_VERSION}" ]]; then
    echo "  • Installed version: ${INSTALLED_VERSION}"
    if [[ "${INSTALLED_VERSION}" != "0.1.1" ]]; then
      echo "  ⚠️  WARNING: Patches are designed for version 0.1.1"
      echo "     Current version ${INSTALLED_VERSION} may have different code structure"
      echo "     Patches may not work correctly - consider updating patches or pinning version"
    fi
  fi
  
  # Check if patches source exists
  if [[ ! -d "${PATCHES_SOURCE}" ]]; then
    echo "❌ Error: Patches source not found at ${PATCHES_SOURCE}"
    return 1
  fi
  
  echo "  • Found patches source at: ${PATCHES_SOURCE}"
  
  # Copy patched sheets/service.py
  if [[ -f "${PATCHES_SOURCE}/sheets/service.py" ]]; then
    echo "  • Patching sheets/service.py..."
    cp "${PATCHES_SOURCE}/sheets/service.py" "${MCP_SUITE_PATH}/sheets/service.py"
    echo "    ✓ sheets/service.py patched"
  else
    echo "⚠️  sheets/service.py patch file not found"
  fi
  
  # Copy patched drive/service.py
  if [[ -f "${PATCHES_SOURCE}/drive/service.py" ]]; then
    echo "  • Patching drive/service.py..."
    cp "${PATCHES_SOURCE}/drive/service.py" "${MCP_SUITE_PATH}/drive/service.py"
    echo "    ✓ drive/service.py patched"
  else
    echo "⚠️  drive/service.py patch file not found"
  fi
  
  # Copy patched docs/service.py
  if [[ -f "${PATCHES_SOURCE}/docs/service.py" ]]; then
    echo "  • Patching docs/service.py..."
    cp "${PATCHES_SOURCE}/docs/service.py" "${MCP_SUITE_PATH}/docs/service.py"
    echo "    ✓ docs/service.py patched"
  else
    echo "⚠️  docs/service.py patch file not found"
  fi
  
  # Copy patched server.py
  if [[ -f "${PATCHES_SOURCE}/server.py" ]]; then
    echo "  • Patching server.py..."
    cp "${PATCHES_SOURCE}/server.py" "${MCP_SUITE_PATH}/server.py"
    echo "    ✓ server.py patched"
  else
    echo "⚠️  server.py patch file not found"
  fi
  
  echo ""
  echo "✅ ==================================================="
  echo "✅ GOOGLE WORKSPACE MCP PATCHES APPLIED"
  echo "✅ ==================================================="
  echo ""
  echo "  • Docs: create_document, get_document, update_document_content,"
  echo "          append_content (all async + asyncio.to_thread)"
  echo "  • Sheets: create_spreadsheet, get_values, update_values,"
  echo "            append_values, clear_values (all async + asyncio.to_thread)"
  echo "  • Drive: search_files, create_folder, move_file,"
  echo "           get_file_metadata (all async + asyncio.to_thread)"
  echo "  • Server: Fixed McpError to use ErrorData instead of strings"
  echo "  • All Google API execute() calls now run in thread pool"
  echo "  • Fixes 'str' object has no attribute 'message' error"
  echo ""
  
  return 0
}

#############################################################################
# Main Patch Dispatcher
#############################################################################
apply_patch_scripts() {
  local PATCH_SCRIPTS="${1}"
  local VENV_DIR="${2}"
  local PROJECT_PATH="${3}"
  
  # Validate parameters
  if [[ -z "${VENV_DIR}" || -z "${PROJECT_PATH}" ]]; then
    echo "❌ Error: Missing required parameters for patch scripts"
    return 1
  fi
  
  # If PATCH_SCRIPTS is empty, skip
  if [[ -z "${PATCH_SCRIPTS}" ]]; then
    echo "• No patch scripts to apply (PATCH_SCRIPTS not set)"
    return 0
  fi
  
  echo ""
  echo "🔧 Applying patch scripts: ${PATCH_SCRIPTS}"
  echo ""
  
  # Split comma-separated values and apply each patch
  IFS=',' read -ra PATCHES <<< "${PATCH_SCRIPTS}"
  for patch_name in "${PATCHES[@]}"; do
    # Trim whitespace
    patch_name=$(echo "${patch_name}" | xargs)
    
    case "${patch_name}" in
      google_workspace)
        patch_google_workspace "${VENV_DIR}" "${PROJECT_PATH}" || {
          echo "⚠️  Warning: google_workspace patch failed (continuing deployment)"
        }
        ;;
      *)
        echo "⚠️  Unknown patch script: ${patch_name} (skipping)"
        ;;
    esac
  done
  
  echo "✅ Patch scripts application completed"
  return 0
}
