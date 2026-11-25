using System.Net;
using System.Text.RegularExpressions;
using Ehr.Data.Accounts;
using Ehr.Data.Audit;
using Ehr.Testing;
using Npgsql;
using Xunit;
using static Ehr.Web.Tests.Browser;

namespace Ehr.Web.Tests;

// Use Case 11, Sign In with Multi-factor Authentication: the test cases TC-11-01 to TC-11-05 from the test plan, run
// against the apps in memory. "Off-site" is the cloud app (apps.Cloud), which is what a clinician outside the clinic
// reaches; "on-site" is the on-prem app. TC-11-05's checks on the running stack (database TLS, plain HTTP, BitLocker)
// and TC-11-06 (synthetic data) look at a real deployment, so they are in tests/stack/UseCase11.Stack.ps1 instead.
public partial class UseCase11Tests(WebApps apps) : IClassFixture<WebApps>
{
    static CancellationToken Cancel => TestContext.Current.CancellationToken;

    // TC-11-01 (FR-28, FR-29): off-site, the password alone leads to the code page; the code signs the clinician in,
    // to the clinician's pages only.
    [Fact]
    public async Task TC_11_01_Off_site_sign_in_needs_the_password_and_the_authenticator_code()
    {
        var clinician = await apps.CreateStaffAsync("Dr. Off Site", StaffRoles.Clinician);
        var jar = new CookieContainer();
        var client = Client(apps.Cloud, jar);

        using var codePage = await PostFormAsync(client, "/sign-in", "/sign-in", ("Input.Email", clinician.Email), ("Input.Password", clinician.Password));
        Assert.Equal("/sign-in/code", PathOf(codePage));
        Assert.Equal(0, await apps.AuditEventsAsync(AuditActions.SignIn, actorId: clinician.Id));

        using var home = await PostFormAsync(client, "/sign-in/code", codePage, ("Code", Totp.Code(clinician.AuthenticatorKey)));
        Assert.Contains("My patients", await ReadAsync(home));

        // Signed in as a clinician, not an admin (FR-29).
        using var staff = await Client(apps.Cloud, jar, followRedirects: false).GetAsync("/admin/staff", Cancel);
        Assert.Equal(HttpStatusCode.Redirect, staff.StatusCode);
        Assert.Equal("/denied", new Uri(Base, staff.Headers.Location!).AbsolutePath);

        Assert.Equal(1, await apps.AuditEventsAsync(AuditActions.SignIn, actorId: clinician.Id));
    }

    // TC-11-02 (FR-28): off-site, a wrong code is refused and recorded, and skipping the code step reaches nothing.
    [Fact]
    public async Task TC_11_02_Off_site_a_wrong_or_skipped_code_signs_nobody_in()
    {
        var clinician = await apps.CreateStaffAsync("Dr. Wrong Code", StaffRoles.Clinician);
        var jar = new CookieContainer();
        var client = Client(apps.Cloud, jar);

        using var codePage = await PostFormAsync(client, "/sign-in", "/sign-in", ("Input.Email", clinician.Email), ("Input.Password", clinician.Password));
        using var wrong = await PostFormAsync(client, "/sign-in/code", codePage, ("Code", Totp.WrongCode(clinician.AuthenticatorKey)));
        Assert.Equal("/sign-in/code", PathOf(wrong));
        Assert.Contains("That code did not match. Try the current code from your app, or a recovery code.", await ReadAsync(wrong));

        // The password is right, but without the code the patients page sends the browser back to sign in.
        using var skipped = await Client(apps.Cloud, jar, followRedirects: false).GetAsync("/patients", Cancel);
        Assert.Equal(HttpStatusCode.Redirect, skipped.StatusCode);
        Assert.Equal("/sign-in", new Uri(Base, skipped.Headers.Location!).AbsolutePath);

        Assert.Equal(0, await apps.AuditEventsAsync(AuditActions.SignIn, actorId: clinician.Id));
        Assert.Contains("wrong code", await ActorReasonsAsync(AuditActions.SignInFailed, clinician.Id));
    }

    // TC-11-03 (FR-25, FR-26): only an admin creates staff accounts, and a new account sets its password and enrolls an
    // authenticator before it reaches anything.
    [Fact]
    public async Task TC_11_03_Only_an_admin_creates_staff_and_a_new_account_sets_a_password_and_mfa_first()
    {
        // A clinician can't create an account.
        var clinician = await apps.CreateStaffAsync("Dr. Not Admin", StaffRoles.Clinician);
        var clinicianSession = await SignInAsync(apps.OnPrem, clinician);
        var refusedEmail = WebApps.NewEmail();
        using var refused = await PostFormAsync(clinicianSession.Client, "/admin/staff", "/patients",
            ("Input.Email", refusedEmail), ("Input.DisplayName", "Not Created"), ("Input.Clinician", "true"), ("Input.Admin", "false"));
        Assert.Equal("/denied", PathOf(refused));
        Assert.Null(await StaffIdAsync(refusedEmail));

        // An admin can, and gets a one-time setup link.
        var admin = await apps.CreateStaffAsync("The Admin", StaffRoles.Admin);
        var adminSession = await SignInAsync(apps.OnPrem, admin);
        var email = WebApps.NewEmail();
        using var invited = await PostFormAsync(adminSession.Client, "/admin/staff", "/admin/staff",
            ("Input.Email", email), ("Input.DisplayName", "Nurse Test 01"), ("Input.Clinician", "true"), ("Input.Admin", "false"));
        var invitedHtml = await ReadAsync(invited);
        Assert.Contains("It isn't shown again", invitedHtml);
        var setupPath = new Uri(WebUtility.HtmlDecode(SetupLink().Match(invitedHtml).Value)).PathAndQuery;
        var newId = await StaffIdAsync(email);
        Assert.NotNull(newId);

        // The new person, in a browser of their own: a password shorter than 12 characters is refused.
        var jar = new CookieContainer();
        var client = Client(apps.OnPrem, jar);
        using var tooShort = await PostFormAsync(client, setupPath, setupPath, ("Input.Password", "short-pw-1"), ("Input.Confirm", "short-pw-1"));
        Assert.Contains("Use at least 12 characters.", await ReadAsync(tooShort));

        const string password = "nurse-test-password-1234";
        using var afterSetup = await PostFormAsync(client, setupPath, setupPath, ("Input.Password", password), ("Input.Confirm", password));
        Assert.Equal("/sign-in", PathOf(afterSetup));

        // The link works once.
        using var again = await client.GetAsync(setupPath, Cancel);
        Assert.Contains("This link is not valid or has already been used.", await ReadAsync(again));

        // The first sign-in goes to enrollment, not in; nothing is reachable before it's done.
        using var enrollPage = await PostFormAsync(client, "/sign-in", afterSetup, ("Input.Email", email), ("Input.Password", password));
        Assert.Equal("/sign-in/enroll", PathOf(enrollPage));
        using var early = await Client(apps.OnPrem, jar, followRedirects: false).GetAsync("/patients", Cancel);
        Assert.Equal("/sign-in", new Uri(Base, early.Headers.Location!).AbsolutePath);

        var key = AuthenticatorSecret().Match(await enrollPage.Content.ReadAsStringAsync(Cancel)).Groups[1].Value;
        using var wrong = await PostFormAsync(client, "/sign-in/enroll", enrollPage, ("Code", Totp.WrongCode(key)));
        Assert.Contains("That code did not match.", await ReadAsync(wrong));

        using var recoveryPage = await PostFormAsync(client, "/sign-in/enroll", wrong, ("Code", Totp.Code(key)));
        var recoveryHtml = await ReadAsync(recoveryPage);
        Assert.Contains("Your recovery codes", recoveryHtml);
        Assert.Equal(StaffSignInRecoveryCodes, RecoveryCode().Matches(recoveryHtml).Count);

        using var patients = await Client(apps.OnPrem, jar, followRedirects: false).GetAsync("/patients", Cancel);
        Assert.Equal(HttpStatusCode.OK, patients.StatusCode);

        Assert.Equal(1, await apps.AuditEventsAsync(AuditActions.StaffInvited, actorId: admin.Id));
        Assert.Equal(1, await apps.AuditEventsAsync(AuditActions.PasswordChanged, actorId: newId));
        Assert.Equal(1, await apps.AuditEventsAsync(AuditActions.MfaEnrolled, actorId: newId));
        Assert.Equal(1, await apps.AuditEventsAsync(AuditActions.SignIn, actorId: newId));
    }

    // TC-11-04 (FR-27, FR-29): staff and patient accounts can't sign in to each other's site, and a staff cookie doesn't
    // open the portal.
    [Fact]
    public async Task TC_11_04_Staff_and_patient_sign_ins_are_separate()
    {
        var clinician = await apps.CreateStaffAsync("Dr. Separate", StaffRoles.Clinician);
        var (patientEmail, patientPassword) = await apps.CreatePatientAccountAsync(await apps.InsertPatientAsync("Jordan", "Portal"));

        using var staffOnPortal = await PostFormAsync(Client(apps.Cloud, new CookieContainer()), "/portal/sign-in", "/portal/sign-in",
            ("Input.Email", clinician.Email), ("Input.Password", clinician.Password));
        Assert.Equal("/portal/sign-in", PathOf(staffOnPortal));
        Assert.Contains("Wrong email or password.", await ReadAsync(staffOnPortal));

        using var patientOnStaff = await PostFormAsync(Client(apps.OnPrem, new CookieContainer()), "/sign-in", "/sign-in",
            ("Input.Email", patientEmail), ("Input.Password", patientPassword));
        Assert.Equal("/sign-in", PathOf(patientOnStaff));
        Assert.Contains("Wrong email or password.", await ReadAsync(patientOnStaff));

        var session = await SignInAsync(apps.Cloud, clinician);
        using var portal = await Client(apps.Cloud, session.Jar, followRedirects: false).GetAsync("/portal", Cancel);
        Assert.Equal(HttpStatusCode.Redirect, portal.StatusCode);
        Assert.Equal("/portal/sign-in", new Uri(Base, portal.Headers.Location!).AbsolutePath);
    }

    // TC-11-05 (NFR-06, FR-28), in transit: the session cookie is only ever sent over HTTPS, never readable by scripts,
    // and never sent with another site's requests.
    [Fact]
    public async Task TC_11_05_The_staff_session_cookie_is_secure_http_only_and_same_site_strict()
    {
        var clinician = await apps.CreateStaffAsync("Dr. Cookie", StaffRoles.Clinician);
        var jar = new CookieContainer();
        using var codePage = await PostFormAsync(Client(apps.Cloud, jar), "/sign-in", "/sign-in", ("Input.Email", clinician.Email), ("Input.Password", clinician.Password));

        using var signedIn = await PostFormAsync(Client(apps.Cloud, jar, followRedirects: false), "/sign-in/code", codePage, ("Code", Totp.Code(clinician.AuthenticatorKey)));

        Assert.Equal(HttpStatusCode.Redirect, signedIn.StatusCode);
        var cookie = Assert.Single(signedIn.Headers.GetValues("Set-Cookie"), header => header.StartsWith("__Host-Ehr.Staff=", StringComparison.Ordinal));
        Assert.Contains("secure", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", cookie, StringComparison.OrdinalIgnoreCase);
    }

    // TC-11-05 (NFR-06), at rest: the stored password is a hash, never the password, and the keys that protect cookies
    // are encrypted before they are stored.
    [Fact]
    public async Task TC_11_05_Passwords_are_stored_hashed_and_cookie_keys_encrypted()
    {
        var clinician = await apps.CreateStaffAsync("Dr. Hashed", StaffRoles.Clinician);
        await SignInAsync(apps.OnPrem, clinician);

        await using var connection = await apps.OpenDatabaseAsync();
        await using (var command = new NpgsqlCommand("SELECT password_hash FROM ehr.staff_users WHERE id = @id", connection))
        {
            command.Parameters.AddWithValue("id", clinician.Id);
            var hash = (string)(await command.ExecuteScalarAsync(Cancel))!;
            Assert.DoesNotContain(clinician.Password, hash);
            // ASP.NET Identity's v3 format: PBKDF2, with the version, settings and salt in front.
            Assert.StartsWith("AQAAAA", hash);
        }

        await using (var command = new NpgsqlCommand("SELECT xml FROM ehr.data_protection_keys", connection))
        await using (var reader = await command.ExecuteReaderAsync(Cancel))
        {
            var keys = 0;
            while (await reader.ReadAsync(Cancel))
            {
                keys++;
                Assert.Contains("encryptedSecret", reader.GetString(0));
            }

            Assert.True(keys > 0, "No Data Protection key was stored.");
        }
    }

    // TC-11-05 (NFR-06), at rest: the authenticator key (the secret behind every code) should not be readable in the
    // database. Today it is: ASP.NET Identity stores it in ehr.staff_user_tokens as plain base32 unless personal data
    // protection is turned on, and the project relies on disk encryption for it instead. Remove Skip once the team has
    // decided to protect it, or delete this test if disk encryption is the accepted control.
    [Fact(Skip = "Known gap: the authenticator key is stored readable in ehr.staff_user_tokens (see the comment above).")]
    public async Task TC_11_05_The_authenticator_key_is_not_stored_readable()
    {
        var clinician = await apps.CreateStaffAsync("Dr. Secret", StaffRoles.Clinician);

        await using var connection = await apps.OpenDatabaseAsync();
        await using var command = new NpgsqlCommand(
            "SELECT value FROM ehr.staff_user_tokens WHERE user_id = @id AND name = 'AuthenticatorKey'", connection);
        command.Parameters.AddWithValue("id", clinician.Id);
        var stored = (string?)await command.ExecuteScalarAsync(Cancel);

        Assert.NotNull(stored);
        Assert.NotEqual(clinician.AuthenticatorKey, stored);
    }

    // StaffSignIn.RecoveryCodes, which the enrollment page shows once.
    const int StaffSignInRecoveryCodes = 8;

    async Task<Guid?> StaffIdAsync(string email)
    {
        await using var connection = await apps.OpenDatabaseAsync();
        await using var command = new NpgsqlCommand("SELECT id FROM ehr.staff_users WHERE email = @email", connection);
        command.Parameters.AddWithValue("email", email);
        return (Guid?)await command.ExecuteScalarAsync(Cancel);
    }

    // The reasons recorded with an account's events of one kind, read as the superuser.
    async Task<List<string>> ActorReasonsAsync(string action, Guid actorId)
    {
        await using var connection = await apps.OpenDatabaseAsync();
        await using var command = new NpgsqlCommand(
            "SELECT reason FROM ehr.audit_events WHERE action = @action AND actor_id = @actor AND reason IS NOT NULL", connection);
        command.Parameters.AddWithValue("action", action);
        command.Parameters.AddWithValue("actor", actorId);
        await using var reader = await command.ExecuteReaderAsync(Cancel);
        var reasons = new List<string>();
        while (await reader.ReadAsync(Cancel))
        {
            reasons.Add(reader.GetString(0));
        }

        return reasons;
    }

    [GeneratedRegex("secret=([A-Z2-7]+)")]
    private static partial Regex AuthenticatorSecret();

    // "code" on main, "mono-code" after the expansion branches' design pass: either is one recovery code.
    [GeneratedRegex("<li class=\"(?:mono-)?code\">")]
    private static partial Regex RecoveryCode();

    [GeneratedRegex("https://[^<\\s]+/sign-in/setup\\?user=[^<\\s]+")]
    private static partial Regex SetupLink();
}
