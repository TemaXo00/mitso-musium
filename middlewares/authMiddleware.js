class AuthMiddleware {
    static async isAdmin(req, res, next) {
        if (!req.session.user) {
            return res.status(401).redirect('/auth/login');
        }

        if (req.session.user.type !== 'Admin') {
            return res.status(403).render('error', {
                message: 'Access denied. Admin privileges required.',
                error: {}
            });
        }

        next();
    }

    static async isAuthor(req, res, next) {
        if (!req.session.user) {
            return res.status(401).redirect('/auth/login');
        }

        if (req.session.user.type !== 'Author' && req.session.user.type !== 'Admin') {
            return res.status(403).render('error', {
                message: 'Access denied. Author privileges required.',
                error: {}
            });
        }

        next();
    }
}

module.exports = AuthMiddleware;