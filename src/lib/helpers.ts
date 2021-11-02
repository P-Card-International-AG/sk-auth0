export function ucFirst(val: string): string {
	return val.charAt(0).toUpperCase() + val.slice(1);
}

export function isSessionExpired(expiresAtSeconds: number): boolean {
	const safeExpiresAtSeconds = expiresAtSeconds - 10 * 60;
	const expiresAt = new Date(safeExpiresAtSeconds * 1000);

	return expiresAt < new Date();
}
