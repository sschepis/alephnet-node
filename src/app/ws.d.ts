/**
 * Local ambient declaration for the `ws` package.
 *
 * `ws` ships no bundled types and this project has no @types/ws. Declaring it
 * as `any` here keeps `ws`-typed code compiling; the application layer itself
 * does not depend on this declaration — it talks to `ws` through the
 * structural `WebSocketLike` / `WebSocketServerLike` interfaces in types.ts.
 */
declare module 'ws';
