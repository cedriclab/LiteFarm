import { createClient } from 'redis';

const CONFIG = {
  password: process.env.REDIS_PASSWORD,
  socket: {
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
  },
};

let client;

/**
 * @function establishConnection
 * @param {Object} config
 * @returns
 */
const establishConnection = async (config) => {
  if (client) {
    return client;
  }

  const _client = createClient(config);

  _client.on('error', (err) => console.error('Redis Client Error', err));

  await _client.connect();

  client = _client;

  return client;
};

export { client, CONFIG, establishConnection };
