export default class Settings {
	id: string;
	version: string;
	versionHistory: [][];
	openRegistration: boolean;
	allowOauthAppsForUsers: boolean;

	constructor(
		id: string,
		version: string,
		versionHistory: [][],
		openRegistration: boolean,
		allowOauthAppsForUsers: boolean
	) {
		this.id = id;
		this.version = version;
		this.versionHistory = versionHistory;
		this.openRegistration = openRegistration;
		this.allowOauthAppsForUsers = allowOauthAppsForUsers;
	}
}