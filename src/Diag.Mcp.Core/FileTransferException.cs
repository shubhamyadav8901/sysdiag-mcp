namespace Diag.Mcp.Core;

/// <summary>Raised when a file could not be written, or the write was not permitted.</summary>
/// <remarks>
/// Lives in the shared core because both sides of every transfer raise it: the server's put_file and
/// get_file, and the relay's push_file and pull_file when a local path is unusable.
/// </remarks>
public sealed class FileTransferException : Exception
{
    public FileTransferException(string message) : base(message)
    {
    }

    public FileTransferException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
