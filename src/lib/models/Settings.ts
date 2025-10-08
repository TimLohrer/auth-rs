export default class Settings {
	_id: string;
	version: string;
	versionHistory: [][];
	openRegistration: boolean;
	allowOauthAppsForUsers: boolean;

	constructor(
		_id: string,
		version: string,
		versionHistory: [][],
		openRegistration: boolean,
		allowOauthAppsForUsers: boolean
	) {
		this._id = _id;
		this.version = version;
		this.versionHistory = versionHistory;
		this.openRegistration = openRegistration;
		this.allowOauthAppsForUsers = allowOauthAppsForUsers;
	}
}