import json
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional

import mcp.types as types
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.shared.exceptions import McpError
from tabulate import tabulate

from mcp_google_suite.auth.google_auth import GoogleAuth
from mcp_google_suite.config import Config
from mcp_google_suite.docs.service import DocsService
from mcp_google_suite.drive.service import DriveService
from mcp_google_suite.sheets.service import SheetsService


# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class GoogleWorkspaceContext:
    """Context for Google Workspace services."""

    auth: GoogleAuth
    drive: DriveService
    docs: DocsService
    sheets: SheetsService


ToolHandler = Callable[[GoogleWorkspaceContext, dict], Awaitable[Dict[str, Any]]]


class GoogleWorkspaceMCPServer:
    """MCP server for Google Workspace operations."""

    def __init__(self, config: Optional[Config] = None, config_path: Optional[str] = None):
        """Initialize the server with optional configuration."""
        logger.info("Initializing GoogleWorkspaceMCPServer")
        self.config = config or Config.load(config_path)
        self._context = None
        self._tool_registry: Dict[str, ToolHandler] = {}

        # Initialize MCP server
        self.server = Server(name="mcp-google-suite", version="0.1.0")

        # Register tools
        self.register_tools()
        self._display_available_tools()

    def _get_tools_list(self) -> List[types.Tool]:
        """Get the list of available tools with their schemas."""
        return [
            types.Tool(
                name="drive_search_files",
                description="Search for files in Google Drive",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query"},
                        "page_size": {
                            "type": "integer",
                            "description": "Number of results to return",
                            "default": 10,
                        },
                    },
                    "required": ["query"],
                },
            ),
            types.Tool(
                name="drive_create_folder",
                description="Create a new folder in Google Drive",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Name of the folder"},
                        "parent_id": {"type": "string", "description": "ID of parent folder"},
                    },
                    "required": ["name"],
                },
            ),
            types.Tool(
                name="docs_create",
                description="Create a new Google Doc",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "description": "Title of the document"},
                        "content": {"type": "string", "description": "Initial content"},
                    },
                    "required": ["title"],
                },
            ),
            types.Tool(
                name="docs_get_content",
                description="Get the contents of a Google Doc",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "document_id": {"type": "string", "description": "ID of the document"}
                    },
                    "required": ["document_id"],
                },
            ),
            types.Tool(
                name="docs_update_content",
                description="Update the content of a Google Doc",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "document_id": {"type": "string", "description": "ID of the document"},
                        "content": {"type": "string", "description": "New content"},
                    },
                    "required": ["document_id", "content"],
                },
            ),
            types.Tool(
                name="sheets_create",
                description="Create a new Google Sheet",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "description": "Title of the spreadsheet"},
                        "sheets": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Sheet names",
                        },
                    },
                    "required": ["title"],
                },
            ),
            types.Tool(
                name="sheets_get_values",
                description="Get values from a Google Sheet range",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "spreadsheet_id": {
                            "type": "string",
                            "description": "ID of the spreadsheet",
                        },
                        "range": {"type": "string", "description": "A1 notation range"},
                    },
                    "required": ["spreadsheet_id", "range"],
                },
            ),
            types.Tool(
                name="sheets_update_values",
                description="Update values in a Google Sheet range",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "spreadsheet_id": {
                            "type": "string",
                            "description": "ID of the spreadsheet",
                        },
                        "range": {"type": "string", "description": "A1 notation range"},
                        "values": {
                            "type": "array",
                            "items": {"type": "array", "items": {"type": "string"}},
                            "description": "2D array of values",
                        },
                    },
                    "required": ["spreadsheet_id", "range", "values"],
                },
            ),
        ]

    def register_tools(self):
        """Register all available tools."""
        try:
            # Register tool handlers
            for tool in self._get_tools_list():
                handler_name = f"_handle_{tool.name}"
                if hasattr(self, handler_name):
                    handler = getattr(self, handler_name)
                    self._tool_registry[tool.name] = handler
                    logger.debug(f"Registered handler for {tool.name}")

            # Register server handlers
            @self.server.list_tools()
            async def list_tools() -> List[types.Tool]:
                return self._get_tools_list()

            @self.server.call_tool()
            async def call_tool(
                name: str, arguments: Optional[Dict[str, Any]] = None
            ) -> List[types.TextContent]:
                if not arguments:
                    raise ValueError("Missing arguments for tool execution")

                if not self._context:
                    raise McpError(
                        types.ErrorData(
                            code=types.INTERNAL_ERROR,
                            message="Server context not initialized"
                        )
                    )

                is_authorized = await self._context.auth.is_authorized()
                if not is_authorized:
                    raise McpError(
                        types.ErrorData(
                            code=types.INTERNAL_ERROR,
                            message="Not authenticated. Please run 'mcp-google auth' first."
                        )
                    )

                handler = self._tool_registry.get(name)
                if not handler:
                    raise ValueError(f"Unknown tool: {name}")

                result = await handler(self._context, arguments)
                return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

        except Exception as e:
            logger.error(f"Error registering tools: {str(e)}", exc_info=True)
            raise

    def _display_available_tools(self):
        """Display available tools in a structured format."""
        try:
            logger.info("Available Tools Summary:")

            # Prepare tool information for display
            tool_info = []
            for name, _handler in self._tool_registry.items():
                tool_schema = next((t for t in self._get_tools_list() if t.name == name), None)
                if tool_schema:
                    required_params = tool_schema.inputSchema.get("required", [])
                    all_params = list(tool_schema.inputSchema.get("properties", {}).keys())
                    optional_params = [p for p in all_params if p not in required_params]

                    tool_info.append(
                        [
                            name,
                            tool_schema.description,
                            ", ".join(required_params) or "None",
                            ", ".join(optional_params) or "None",
                        ]
                    )

            # Create a formatted table
            headers = ["Tool Name", "Description", "Required Parameters", "Optional Parameters"]
            table = tabulate(tool_info, headers=headers, tablefmt="grid")

            # Print the table with a border
            border_line = "=" * len(table.split("\n")[0])
            logger.info("\n" + border_line)
            logger.info("MCP Google Workspace Tools")
            logger.info(border_line)
            logger.info("\n" + table)
            logger.info(border_line + "\n")

            # Log summary statistics
            logger.info(f"Total tools available: {len(tool_info)}")
            logger.info(
                f"Tools with required parameters: {sum(1 for t in tool_info if t[2] != 'None')}"
            )
            logger.info(
                f"Tools with optional parameters: {sum(1 for t in tool_info if t[3] != 'None')}"
            )

        except Exception as e:
            logger.error(f"Error displaying tools: {str(e)}", exc_info=True)

    @asynccontextmanager
    async def lifespan(self) -> AsyncIterator[GoogleWorkspaceContext]:
        """Manage Google Workspace services lifecycle."""
        try:
            auth = GoogleAuth(config=self.config)
            drive = DriveService(auth)
            docs = DocsService(auth)
            sheets = SheetsService(auth)
            context = GoogleWorkspaceContext(auth=auth, drive=drive, docs=docs, sheets=sheets)
            self._context = context
            yield context
        finally:
            self._context = None

    async def run(self, read_stream, write_stream, init_options: InitializationOptions) -> None:
        """Run the server with the given streams and initialization options."""
        async with self.lifespan():
            await self.server.run(read_stream, write_stream, init_options)

    async def _handle_drive_search_files(
        self, context: GoogleWorkspaceContext, arguments: dict
    ) -> Dict[str, Any]:
        """Handle drive search files requests."""
        query = arguments.get("query")
        page_size = arguments.get("page_size", 10)

        if not query:
            raise ValueError("Search query is required")

        logger.debug(f"Drive search request - Query: {query}, Page Size: {page_size}")
        result = await context.drive.search_files(query=query, page_size=page_size)
        logger.debug(f"Drive search completed - Found {len(result.get('files', []))} files")
        return result

    async def _handle_drive_create_folder(
        self, context: GoogleWorkspaceContext, arguments: dict
    ) -> Dict[str, Any]:
        """Handle drive create folder requests."""
        name = arguments.get("name")
        parent_id = arguments.get("parent_id")

        if not name:
            raise ValueError("Folder name is required")

        logger.debug(f"Creating folder - Name: {name}, Parent: {parent_id or 'root'}")
        result = await context.drive.create_folder(name=name, parent_id=parent_id)
        logger.debug(f"Folder created - ID: {result.get('id')}")
        return result

    async def _handle_docs_create(
        self, context: GoogleWorkspaceContext, arguments: dict
    ) -> Dict[str, Any]:
        """Handle docs create requests."""
        title = arguments.get("title")
        content = arguments.get("content")

        if not title:
            raise ValueError("Document title is required")

        logger.debug(f"Creating document - Title: {title}, Content length: {len(content or '')}")
        result = await context.docs.create_document(title=title, content=content)
        logger.debug(f"Document created - ID: {result.get('documentId')}")
        return result

    async def _handle_docs_get_content(
        self, context: GoogleWorkspaceContext, arguments: dict
    ) -> Dict[str, Any]:
        """Handle docs get content requests."""
        document_id = arguments.get("document_id")

        if not document_id:
            raise ValueError("Document ID is required")

        logger.debug(f"Getting document content - ID: {document_id}")
        result = await context.docs.get_document_content(document_id=document_id)
        logger.debug("Document content retrieved successfully")
        return result

    async def _handle_docs_update_content(
        self, context: GoogleWorkspaceContext, arguments: dict
    ) -> Dict[str, Any]:
        """Handle docs update content requests."""
        document_id = arguments.get("document_id")
        content = arguments.get("content")

        if not document_id or content is None:
            raise ValueError("Both document_id and content are required")

        logger.debug(f"Updating document - ID: {document_id}, Content length: {len(content)}")
        result = await context.docs.update_document_content(
            document_id=document_id, content=content
        )
        logger.debug("Document content updated successfully")
        return result

    async def _handle_sheets_create(
        self, context: GoogleWorkspaceContext, arguments: dict
    ) -> Dict[str, Any]:
        """Handle sheets create requests."""
        title = arguments.get("title")
        sheets = arguments.get("sheets", [])

        if not title:
            raise ValueError("Spreadsheet title is required")

        logger.debug(f"Creating spreadsheet - Title: {title}, Sheets: {sheets}")
        result = await context.sheets.create_spreadsheet(title=title, sheets=sheets)
        logger.debug(f"Spreadsheet created - ID: {result.get('spreadsheetId')}")
        return result

    async def _handle_sheets_get_values(
        self, context: GoogleWorkspaceContext, arguments: dict
    ) -> Dict[str, Any]:
        """Handle sheets get values requests."""
        spreadsheet_id = arguments.get("spreadsheet_id")
        range_name = arguments.get("range")

        if not spreadsheet_id or not range_name:
            raise ValueError("Both spreadsheet_id and range are required")

        logger.debug(f"Getting sheet values - ID: {spreadsheet_id}, Range: {range_name}")
        result = await context.sheets.get_values(
            spreadsheet_id=spreadsheet_id, range_name=range_name
        )
        logger.debug(f"Sheet values retrieved - Row count: {len(result.get('values', []))}")
        return result

    async def _handle_sheets_update_values(
        self, context: GoogleWorkspaceContext, arguments: dict
    ) -> Dict[str, Any]:
        """Handle sheets update values requests."""
        spreadsheet_id = arguments.get("spreadsheet_id")
        range_name = arguments.get("range")
        values = arguments.get("values")

        if not spreadsheet_id or not range_name or values is None:
            raise ValueError("spreadsheet_id, range, and values are required")

        logger.debug(f"Updating sheet values - ID: {spreadsheet_id}, Range: {range_name}")
        result = await context.sheets.update_values(
            spreadsheet_id=spreadsheet_id, range_name=range_name, values=values
        )
        logger.debug(f"Sheet values updated - Updated cells: {result.get('updatedCells', 0)}")
        return result

    def list_tools_table(self) -> str:
        """List available tools in a table format."""
        try:
            # Prepare tool information for display
            tool_info = []
            for name, _handler in self._tool_registry.items():
                tool_schema = next((t for t in self._get_tools_list() if t.name == name), None)
                if tool_schema:
                    tool_info.append([name, tool_schema.description])

            return tabulate(tool_info, headers=["Tool", "Description"], tablefmt="grid")
        except Exception as e:
            logger.error(f"Error listing tools: {e}")
            return "Error listing tools"

