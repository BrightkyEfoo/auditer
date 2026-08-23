import { createAppAuth } from "@octokit/auth-app";

/**
 * Mint a short-lived (~1h) GitHub App installation token for cloning a private
 * repo. The token is never persisted — it lives only for the duration of the
 * clone and is dropped after. Returns undefined when the app isn't configured
 * or the connection has no installation (→ caller falls back to public clone).
 */
export async function mintInstallationToken(
  installationId: string | null | undefined,
): Promise<string | undefined> {
  const appId = process.env.GITHUB_APP_ID;
  const privateKey = process.env.GITHUB_APP_PRIVATE_KEY?.replace(/\\n/g, "\n");
  if (!appId || !privateKey || !installationId) return undefined;

  try {
    const auth = createAppAuth({ appId, privateKey });
    const { token } = await auth({
      type: "installation",
      installationId: Number(installationId),
    });
    return token;
  } catch {
    return undefined; // fall back to unauthenticated
  }
}
