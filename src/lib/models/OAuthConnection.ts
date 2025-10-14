import type OAuthApplication from "./OAuthApplication";

export default class OAuthConnection {
	id: string;
	application: OAuthApplication;
	userId: string;
	scope: string[];
	expiresIn: number;
	createdAt: number;

	constructor(
		id: string,
		application: OAuthApplication,
		userId: string,
		scope: string[],
		expiresIn: number,
		createdAt: number
	) {
		this.id = id;
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