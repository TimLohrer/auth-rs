export default class UserUpdates {
	email: string | null;
	password: string | null;
	oldPassword: string | null;
	firstName: string | null;
	lastName: string | null;
	roles: string[] | null;
	disabled: boolean | null;

	constructor({
		email,
		password,
		oldPassword,
		firstName,
		lastName,
		roles,
		disabled
	}: {
		email: string | null;
		password: string | null;
		oldPassword: string | null;
		firstName: string | null;
		lastName: string | null;
		roles: string[] | null;
		disabled: boolean | null;
	}) {
		this.email = email;
		this.password = password;
		this.oldPassword = oldPassword;
		this.firstName = firstName;
		this.lastName = lastName;
		this.roles = roles;
		this.disabled = disabled;
	}
}