/**
 * Auto-generated Code Mode TypeScript interface definitions for Hermes & MCP Tools.
 * Inspired by @cloudflare/codemode.
 */
export interface HermesTools {
  /** Search the web for information. */
  web_search(query: string, limit?: number): Promise<Record<string, any>>;
  /** Extract content from web page URLs. */
  web_extract(urls: string[], char_limit?: number | null): Promise<Record<string, any>>;
  /** Read text file with line numbers and pagination. */
  read_file(path: string, offset?: number, limit?: number): Promise<Record<string, any>>;
  /** Write content to a file, completely replacing existing content. */
  write_file(path: string, content: string): Promise<Record<string, any>>;
  /** Search file contents or find files by name. */
  search_files(pattern: string, target?: string, path?: string, file_glob?: string | null, limit?: number): Promise<Record<string, any>>;
  /** Targeted find-and-replace edits in files. */
  patch(path: string, old_string: string, new_string: string, replace_all?: boolean): Promise<Record<string, any>>;
  /** Execute shell commands on the OS. */
  terminal(command: string, timeout?: number | null, workdir?: string | null): Promise<Record<string, any>>;
}

export declare const hermes: HermesTools;