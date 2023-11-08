import express, { Request } from 'express';
import { json, urlencoded } from 'body-parser';
import { compare, hash } from 'bcrypt';
import { createHmac } from 'crypto';
import base64url from 'base64url';
import { Client } from 'pg';

// Constants
const app = express();
const port = 8080;
const corsOptions = {
  origin: '*',
  optionsSuccessStatus: 200
};

app.use(json());
app.use(urlencoded({ extended: true }));
app.use(require('cors')(corsOptions));

const client = new Client({
  user: 'user',
  password: 'user123',
  host: 'db',
  database: 'app'
});

interface AuthRequest {
  username: string;
  password: string;
}

interface User {
  id: string;
  username: string;
  password: string;
}

const validAuthRequest = (req: Request): boolean => {
  return (
    req.body.username !== undefined &&
    req.body.password !== undefined &&
    typeof req.body.password === 'string' &&
    typeof req.body.username === 'string'
  );
};

app.post('/register', async (req, res) => {
  try {
    if (!validAuthRequest(req)) {
      return res.status(400).send();
    }
    const body: AuthRequest = req.body;
    const hashed = await hash(body.password, 10);
    await client.query('INSERT INTO AppUser (username, password) VALUES ($1::text, $2::text)', [
      body.username,
      hashed
    ]);
    return res.status(200).send();
  } catch (e) {
    console.error(e);
    return res.status(500).send();
  }
});

app.post('/login', async (req, res) => {
  try {
    if (!validAuthRequest(req)) {
      return res.status(400).send();
    }
    const body: AuthRequest = req.body;
    const users = await client.query(
      'SELECT id, username, password FROM AppUser WHERE username = $1::text',
      [body.username]
    );
    if (users.rowCount === 0) {
      return res.status(400).json({ message: 'Invalid username' });
    }
    const user: User = users.rows[0];
    const passwordMatches = await compare(body.password, user.password);
    if (!passwordMatches) return res.status(400).json({ message: 'Invalid password' });
    const header = {
      alg: 'HS256',
      typ: 'JWT'
    };
    const exp = new Date();
    exp.setMonth(exp.getMonth() + 1);
    const payload = {
      exp: Math.floor(exp.getTime() / 1000),
      id: user.id,
      other: 'data'
    };
    const headerAndPayload =
      base64url(JSON.stringify(header)) + '.' + base64url(JSON.stringify(payload));
    const hmac = createHmac('sha256', 'verysecretword');
    const secret = hmac.update(headerAndPayload);
    const token = headerAndPayload + '.' + secret.digest('base64url');
    return res.status(200).send({ token });
  } catch (e) {
    console.error(e);
    return res.status(500).send();
  }
});

interface ParsedPayload {
  id: string;
  exp: string;
}

app.post('/authorized-action', async (req, res) => {
  try {
    if (
      req.header('Authorization') === undefined ||
      !req.header('Authorization')!.toLocaleLowerCase().startsWith('bearer ') ||
      req.header('Authorization')!.split(' ').length != 2
    ) {
      return res.status(400).send({ message: 'No authorization header' });
    }

    const [_, token] = req.header('Authorization')!.split(' ');
    const tokenParts = token.split('.');
    if (tokenParts.length != 3) {
      return res.status(400).send({ message: 'Invalid JWT token' });
    }
    const hmac = createHmac('sha256', 'verysecretword');
    const secret = hmac.update(tokenParts[0] + '.' + tokenParts[1]);
    if (secret.digest('base64url') != tokenParts[2]) return res.status(401).send();
    const payload = base64url.decode(tokenParts[1]);
    let parsedPayload: ParsedPayload;
    try {
      parsedPayload = JSON.parse(payload);
    } catch (e) {
      return res.status(400).send({ message: 'Invalid JWT payload' });
    }
    if (typeof parsedPayload.id != 'string' || typeof parsedPayload.exp != 'number') {
      return res.status(400).send({ message: 'Invalid data in JWT payload' });
    }
    if (new Date(parsedPayload.exp * 1000) <= new Date()) {
      return res.status(401).send();
    }
    console.log(`User of id ${parsedPayload.id} is taking an authorized action.`);
    return res.status(200).send();
  } catch (e) {
    console.error(e);
    return res.status(500).send();
  }
});

process.on('SIGINT', async () => {
  await client.end();
  process.exit();
});

app.listen(port, async () => {
  await client.connect();
  console.log(`Listening on port ${port}`);
});
