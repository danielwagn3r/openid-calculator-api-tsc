import * as dotenv from "dotenv";
dotenv.config();

import express, { Application, Request, Response } from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import helmet from "helmet";
import winston, { format, transports } from "winston";
import expressWinston from "express-winston";
import jsonwebtoken from "jsonwebtoken"

import { expressJwtSecret, GetVerificationKey } from "jwks-rsa"
import { expressjwt } from "express-jwt";
// @ts-ignore'
import jwtScope from "express-jwt-scope";
import { check, validationResult } from "express-validator";

const loggerSettings = {
    transports: [new transports.Console()],
    format: format.combine(
        format.colorize(),
        format.timestamp(),
        format.printf(({ timestamp, level, message }) => {
            return `[${timestamp}] ${level}: ${message}`;
        })
    ),
    expressFormat: true,
    meta: true,
    defaultMeta: {
        service: 'calculator-api'
    }
};

const logger = winston.createLogger(loggerSettings);

export const checkJwt = expressjwt({
    secret: expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `${process.env.ISSUER}/.well-known/jwks.json`
    }) as GetVerificationKey,

    audience: `${process.env.AUDIENCE}`,
    issuer: `${process.env.ISSUER}/`,
    algorithms: ['RS256']
});

const doubleScope = jwtScope(["calc:double"], {requireAll: true});
const squareScope = jwtScope(["calc:square"], {requireAll: true});

const app: Application = express();

app.use(expressWinston.logger(loggerSettings));

app.use(helmet());

// if you want anyone to be able to connect
app.use(cors({ origin: true }))

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get('/api/double/:number', checkJwt, doubleScope, [check('number').isInt()], function (req: Request, res: Response) {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(422).json({ errors: errors.array() });
    }

    var number = parseInt(req.params.number, 10);
    var double = number * 2;
    res.json({ result: double });
});

app.get('/api/square/:number', checkJwt, squareScope, [check('number').isInt()], function (req: Request, res: Response) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({ errors: errors.array() });
    }

    var number = parseInt(req.params.number, 10);
    var square = number * number;
    res.json({ result: square });
});

app.get('/api/tokeninfo', checkJwt, function (req: Request, res: Response) {
    var token = req.headers.authorization?.split(' ')[1] as string;
    var decoded = jsonwebtoken.decode(token)

    res.status(200).send(decoded);
});


app.get('/', (req: Request, res: Response) => {
    res.send('Healthy')
})

const PORT = process.env.PORT || 5001;

app.listen(PORT, () => {
    logger.info(`Server is running on PORT ${PORT}`)
})
