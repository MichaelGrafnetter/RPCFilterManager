using System.Runtime.InteropServices;
using System.Security;
using Windows.Win32.System.Rpc;

namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Enables passing a particular user name and password to the run-time library for the purpose of authentication.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal sealed class SEC_WINNT_AUTH_IDENTITY_W : IDisposable
{
    /// <summary>
    /// String containing the user name.
    /// </summary>
    [MarshalAs(UnmanagedType.LPWStr)]
    public readonly string? User;

    /// <summary>
    /// Number of characters in User, excluding the terminating NULL.
    /// </summary>
    private int UserLength;

    /// <summary>
    /// String containing the domain or workgroup name.
    /// </summary>
    [MarshalAs(UnmanagedType.LPWStr)]
    public readonly string? Domain;

    /// <summary>
    /// Number of characters in Domain, excluding the terminating NULL.
    /// </summary>
    private int DomainLength;

    /// <summary>
    /// String containing the user's password in the domain or workgroup.
    /// </summary>
    public readonly SafeUnicodeSecureStringPointer? Password;

    /// <summary>
    /// Number of characters in Password, excluding the terminating NULL.
    /// </summary>
    private int PasswordLength;

    /// <summary>
    /// Flags used to specify ANSI or UNICODE.
    /// </summary>
    private SEC_WINNT_AUTH_IDENTITY Flags;

    public SEC_WINNT_AUTH_IDENTITY_W(string? user, string? domain, SecureString? password)
    {
        this.User = user;
        this.UserLength = user?.Length ?? 0;

        this.Domain = domain;
        this.DomainLength = domain?.Length ?? 0;

        if (password != null)
        {
            Password = new SafeUnicodeSecureStringPointer(password);
            PasswordLength = password.Length;
        }

        Flags = SEC_WINNT_AUTH_IDENTITY.SEC_WINNT_AUTH_IDENTITY_UNICODE;
    }

    public void Dispose()
    {
        this.Password?.Dispose();
        this.PasswordLength = 0;
    }
}
