import type OAuthApplication from "./OAuthApplication";

export default class OAuthConnection {
	_id: string;
	application: OAuthApplication;
	userId: string;
	scope: string[];
	expiresIn: number;
	createdAt: number;

	constructor(
		_id: string,
		application: OAuthApplication,
		userId: string,
		scope: string[],
		expiresIn: number,
		createdAt: number
	) {
		this._id = _id;
		this.application = application;
		this.userId = userId;
		this.scope = scope;
		this.expiresIn = expiresIn;
		this.createdAt = createdAt;
	}

	static getCreatedAt(connection: OAuthConnection): Date {
		return new Date(connection.createdAt);
	}

	static getExpiresAt(connection: OAuthConnection): Date {
		return new Date(connection.createdAt + connection.expiresIn - Date.now());
	}
}