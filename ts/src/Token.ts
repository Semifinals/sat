import { Buffer } from "buffer"
import { createHmac } from "node:crypto"

export class Token {
  /**
   * The Semifinals Authentication Token epoch time (1st January 2023) in seconds.
   */
  public static epoch: number = Date.UTC(2023, 0, 1) / 1000

  /**
   * The separator used to partition the token.
   */
  public static separator: string = "."

  /**
   * Generate a token for the given ID.
   * @param id The ID for the token
   * @param secret The secret used for the sha256 algorithm
   * @returns The generated token
   */
  public static generate(id: string, secret: string): string {
    const timestamp = Math.round(Date.now() / 1000) - Token.epoch

    const payload = Token.payload(id, timestamp)
    const signature = Token.sign(payload, secret)

    return payload + Token.separator + signature
  }

  /**
   * Generate a payload using the given ID and timestamp.
   * @param id The ID for the token
   * @param timestamp The timestamp for the token
   * @returns The resulting payload
   */
  public static payload(id: string, timestamp: number): string {
    const encodedId = Token.toBase64(id)
    const encodedTimestamp = Token.toBase64(String(timestamp))

    return encodedId + Token.separator + encodedTimestamp
  }

  /**
   * Generate a signature for the given payload.
   * @param payload The payload to sign
   * @param secret The secret used for the sha256 algorithm
   * @returns The generated signature
   */
  public static sign(payload: string, secret: string): string {
    const hasher = createHmac("sha256", secret)
    const signature = hasher.update(payload).digest("base64")

    return signature
  }

  /**
   * Validate that the token looks correct in structure.
   * @param token The token to validate
   * @returns Whether or not the token is valid
   */
  public static validate(token: string): boolean {
    const parts = Token.split(token)
    if (parts.length !== 3) return false

    const userId = Token.toUtf8(parts[0])
    if (userId.length === 0) return false

    const unparsedTimestamp = Token.toUtf8(parts[1])
    if (unparsedTimestamp.length === 0) return false

    const timestamp = parseInt(unparsedTimestamp)
    if (typeof timestamp !== "number") return false

    const signature = parts[2]
    if (signature.length === 0) return false

    return true
  }

  /**
   * Verify that the signature of the token is authentic.
   * @param token The full token
   * @param secret The secret used for the sha256 algorithm
   * @returns Whether or not the token was verified to be authentic
   */
  public static verify(token: string, secret: string): boolean {
    if (!Token.validate(token)) return false

    const parts = Token.split(token)

    const id = Token.toUtf8(parts[0])
    const timestamp = parseInt(Token.toUtf8(parts[1]))
    const signature = parts[2]

    const payload = Token.payload(id, timestamp)
    const generatedSignature = Token.sign(payload, secret)

    return signature === generatedSignature
  }

  /**
   * Get the ID of the token.
   * @param token The full token
   * @returns The ID of the token
   */
  public static getId(token: string): string | null {
    if (!Token.validate(token)) return null

    const parts = Token.split(token)
    const id = Token.toUtf8(parts[0])

    return id
  }

  /**
   * Get the timestamp of the token.
   * @param token The full token
   * @returns The Semifinals epoch timestamp of the token in seconds
   */
  public static getTimestamp(token: string): number | null {
    if (!Token.validate(token)) return null

    const parts = Token.split(token)
    const timestamp = parseInt(Token.toUtf8(parts[1]))

    return Token.epoch + timestamp
  }

  /**
   * Get the signature from a token.
   * @param token The full token
   * @returns The token's signature
   */
  public static getSignature(token: string): string | null {
    if (!Token.validate(token)) return null

    const parts = Token.split(token)
    const signature = parts[2]

    return signature
  }

  /**
   * Split a string into parts by the token separator.
   * @param str The string to split
   * @returns The string split into its parts
   */
  public static split(str: string): string[] {
    return str.split(Token.separator)
  }

  /**
   * Convert a utf8 string into base64.
   * @param str The utf8 string
   * @returns The string converted to base64
   */
  public static toBase64(str: string): string {
    return Buffer.from(str, "utf8").toString("base64")
  }

  /**
   * Convert a base64 string into utf8.
   * @param str The base64 string
   * @returns The string converted to utf8
   */
  public static toUtf8(str: string): string {
    return Buffer.from(str, "base64").toString("utf8")
  }
}
