"""
Auto-generated Code Mode Python client wrappers for Hermes & MCP Tools.
Enables multi-tool execution in a single block without round-trip token overhead.
"""
from hermes_tools import (
    web_search as _ws,
    web_extract as _we,
    read_file as _rf,
    write_file as _wf,
    search_files as _sf,
    patch as _pt,
    terminal as _tm,
    json_parse, retry, shell_quote
)

class HermesCodeMode:
    """Programmatic API interface for Hermes Code Mode execution."""
    @staticmethod
    def web_search(query: str, limit: int = 5) -> dict:
        """Search the web for information."""
        return _ws(query=query, limit=limit)

    @staticmethod
    def web_extract(urls: list[str], char_limit: int = None) -> dict:
        """Extract content from web page URLs."""
        return _we(urls=urls, char_limit=char_limit)

    @staticmethod
    def read_file(path: str, offset: int = 1, limit: int = 2000) -> dict:
        """Read text file with line numbers and pagination."""
        return _rf(path=path, offset=offset, limit=limit)

    @staticmethod
    def write_file(path: str, content: str) -> dict:
        """Write content to a file, completely replacing existing content."""
        return _wf(path=path, content=content)

    @staticmethod
    def search_files(pattern: str, target: str = 'content', path: str = '.', file_glob: str = None, limit: int = 50) -> dict:
        """Search file contents or find files by name."""
        return _sf(pattern=pattern, target=target, path=path, file_glob=file_glob, limit=limit)

    @staticmethod
    def patch(path: str, old_string: str, new_string: str, replace_all: bool = False) -> dict:
        """Targeted find-and-replace edits in files."""
        return _pt(path=path, old_string=old_string, new_string=new_string, replace_all=replace_all)

    @staticmethod
    def terminal(command: str, timeout: int = None, workdir: str = None) -> dict:
        """Execute shell commands on the OS."""
        return _tm(command=command, timeout=timeout, workdir=workdir)
