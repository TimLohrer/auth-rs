export default class OAuthApplication {
	id: string;
	name: string;
	description: string | null;
	redirectUris: string[];
	owner: string;
	secret: string | null;
	createdAt: number;

	constructor(
		id: string,
		name: string,
		description: string | null,
		redirectUris: string[],
		owner: string,
		secret: string | null,
		createdAt: number
	) {
		this.id = id;
		this.name = name;
		this.description = description;
		this.redirectUris = redirectUris;
		this.owner = owner;
		this.secret = secret;
		this.createdAt = createdAt;
	}

	static getCreatedAt(application: OAuthApplication): Date {
		return new Date(application.createdAt);
	}
}