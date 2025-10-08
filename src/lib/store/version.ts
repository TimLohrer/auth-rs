import { writable, derived } from 'svelte/store';

// Get version from build-time environment variable
export const version = writable<string>(__VERSION__);
export const latestVersion = writable<string | null>(null);
export const updateCheckLoading = writable<boolean>(false);
export const updateCheckError = writable<string | null>(null);

// Derived store to check if an update is available
export const updateAvailable = derived(
	[version, latestVersion],
	([$version, $latestVersion]) => {
		if (!$latestVersion || $version === 'dev') return false;
		
		// Parse versions (assuming semver format like v1.2.3)
		const currentVersion = parseVersion($version);
		const latest = parseVersion($latestVersion);
		
		if (!currentVersion || !latest) return false;
		
		return compareVersions(latest, currentVersion) > 0;
	}
);

// Parse version string to comparable format
function parseVersion(versionStr: string): { major: number; minor: number; patch: number } | null {
	// Remove 'v' prefix if present
	const cleaned = versionStr.replace(/^v/, '');
	const parts = cleaned.split('.');
	
	if (parts.length !== 3) return null;
	
	const major = parseInt(parts[0], 10);
	const minor = parseInt(parts[1], 10);
	const patch = parseInt(parts[2], 10);
	
	if (isNaN(major) || isNaN(minor) || isNaN(patch)) return null;
	
	return { major, minor, patch };
}

// Compare two version objects (returns > 0 if a > b, < 0 if a < b, 0 if equal)
function compareVersions(
	a: { major: number; minor: number; patch: number },
	b: { major: number; minor: number; patch: number }
): number {
	if (a.major !== b.major) return a.major - b.major;
	if (a.minor !== b.minor) return a.minor - b.minor;
	return a.patch - b.patch;
}

// Check for latest release from GitHub API
export async function checkForUpdates(): Promise<void> {
	updateCheckLoading.set(true);
	updateCheckError.set(null);
    
	try {
		const response = await fetch('https://api.github.com/repos/TimLohrer/auth-rs/releases/latest');

		if (response.status === 404) {
			// No releases exist yet
			latestVersion.set(null);
			return;
		}

		if (!response.ok) {
			throw new Error(`Failed to fetch latest release: ${response.status}`);
		}

		const release = await response.json();
		latestVersion.set(release.tag_name);
	} catch (error) {
		console.error('Error checking for updates:', error);
		updateCheckError.set(error instanceof Error ? error.message : 'Unknown error');
	} finally {
		updateCheckLoading.set(false);
	}
}
