import asyncio
from typing import Any, Dict, Optional

from googleapiclient.errors import HttpError

from mcp_google_suite.base_service import BaseGoogleService


class DocsService(BaseGoogleService):
    """Google Docs service implementation."""

    def __init__(self, auth=None):
        super().__init__("docs", "v1", auth)

    async def create_document(self, title: str, content: Optional[str] = None) -> Dict[str, Any]:
        """Create a new Google Doc with optional initial content."""
        try:
            service = await self.get_service()
            doc = await asyncio.to_thread(service.documents().create(body={"title": title}).execute)

            if content:
                await self.update_document_content(doc["documentId"], content)

            return {"success": True, "document": doc}
        except HttpError as error:
            return {"success": False, **self.handle_error(error)}

    async def get_document(self, document_id: str) -> Dict[str, Any]:
        """Get the contents of a Google Doc."""
        try:
            service = await self.get_service()
            document = await asyncio.to_thread(
                service.documents().get(documentId=document_id).execute
            )
            return {"success": True, "document": document}
        except HttpError as error:
            return {"success": False, **self.handle_error(error)}

    async def get_document_content(self, document_id: str) -> Dict[str, Any]:
        """Get the contents of a Google Doc (alias for get_document)."""
        return await self.get_document(document_id)

    async def update_document_content(self, document_id: str, content: str) -> Dict[str, Any]:
        """Update the content of a Google Doc."""
        try:
            service = await self.get_service()
            requests = [{"insertText": {"location": {"index": 1}, "text": content}}]

            result = await asyncio.to_thread(
                service.documents()
                .batchUpdate(documentId=document_id, body={"requests": requests})
                .execute
            )

            return {"success": True, "result": result}
        except HttpError as error:
            return {"success": False, **self.handle_error(error)}

    async def append_content(self, document_id: str, content: str) -> Dict[str, Any]:
        """Append content to the end of a Google Doc."""
        try:
            document = await self.get_document(document_id)
            if not document["success"]:
                return document

            service = await self.get_service()
            end_index = document["document"]["body"]["content"][-1]["endIndex"]

            requests = [{"insertText": {"location": {"index": end_index - 1}, "text": content}}]

            result = await asyncio.to_thread(
                service.documents()
                .batchUpdate(documentId=document_id, body={"requests": requests})
                .execute
            )

            return {"success": True, "result": result}
        except HttpError as error:
            return {"success": False, **self.handle_error(error)}

