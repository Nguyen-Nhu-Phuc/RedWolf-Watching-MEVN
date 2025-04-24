export default function authHeader() {
    let user = JSON.parse(sessionStorage.getItem('membership'));

    if (user && user.token) {
        return { 'Authentication': 'Bearer' + user.token };
    } else {
        return {};
    }
}