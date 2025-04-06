# Who_Needs_lsass


**Functionality:**

This Windows C++ utility is designed to request and export user certificates from an Active Directory Certificate Authority (AD CS) on behalf of other logged-in users on the same machine. Its primary use case is for administrators or privileged processes needing to obtain certificates for standard users.

**Workflow:**

1.  **Token Discovery:** The tool scans the system's handle table using `NtQuerySystemInformation(SystemHandleInformation)`. It identifies handles belonging to other processes, duplicates them (`DuplicateHandle`), and checks if they represent `Token` objects (`NtQueryObject(ObjectTypeInformation)`).
2.  **Token Analysis:** For valid user tokens (`SidTypeUser`), it extracts information such as the username, domain, session ID, token type (primary/impersonation), impersonation level, and integrity level using `GetTokenInformation`. Unique, interactive user tokens are stored and presented to the operator.
3.  **Certificate Request (as User):** Upon selecting a target token ID, the tool performs the following actions *under the security context of the chosen user*:
    * Generates a dynamic `.inf` configuration file tailored to the user and domain.
    * Executes `certreq.exe -new`, `-submit` (using the "User" template), and `-accept` commands via `CreateProcessAsUserW` (or `CreateProcessWithTokenW` as a fallback) to request and install the certificate in the target user's store.
4.  **PFX Export (as User):**
    * Retrieves the thumbprint of the newly installed certificate using a PowerShell command, executed via `CreateProcessAsUserW`.
    * Exports the certificate and its private key to a password-protected PFX file (saved in `C:\Users\Public\`) using another PowerShell command (`Export-PfxCertificate`), again executed via `CreateProcessAsUserW`.

**Technical Implementation:**

The tool relies heavily on Windows API calls for process and token manipulation, including privilege elevation (`EnablePrivilege` for `SeDebugPrivilege`, `SeAssignPrimaryTokenPrivilege`), handle enumeration, token duplication, and impersonated process creation. It interfaces with external command-line utilities (`certreq.exe`, `powershell.exe`) to interact with the AD CS and the certificate store.
