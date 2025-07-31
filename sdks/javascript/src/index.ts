/**
 * Universal AI Governor JavaScript/TypeScript SDK
 * 
 * A comprehensive SDK for interacting with the Universal AI Governor service.
 * Supports both Node.js and browser environments with TypeScript support.
 */

export { GovernorClient } from './client';
export { GovernorWebSocketClient } from './websocket';
export * from './types';
export * from './config';
export * from './errors';
export * from './utils';

// Version information
export const VERSION = '1.0.0';

// Default export for convenience
export { GovernorClient as default } from './client';
