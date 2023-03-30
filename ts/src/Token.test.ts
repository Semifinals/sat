import { Token } from "./Token"

const testSecret = "secret"

describe("Token", () => {
  describe("epoch", () => {
    it("is correct time", () => {
      // Arrange
      const epoch = 1672531200

      // Act
      const res = Token.epoch

      // Assert
      expect(res).toBe(epoch)
    })
  })

  describe("separator", () => {
    it("is correct separator", () => {
      // Arrange
      const separator = "."

      // Act
      const res = Token.separator

      // Assert
      expect(res).toBe(separator)
    })
  })

  describe("generate", () => {
    it("generates a valid token", () => {
      // Arrange
      const id = "test"

      // Act
      const res = Token.generate(id, testSecret)

      // Assert
      const resId = Token.getId(res)!
      expect(resId).toBe(id)

      const resTimestamp = Token.getTimestamp(res)! - Token.epoch
      const payload = Token.payload(resId, resTimestamp)
      const signature = Token.sign(payload, testSecret)

      const resSignature = Token.getSignature(res)
      expect(resSignature).toBe(signature)
    })
  })

  describe("payload", () => {
    it.each([
      [["id", 1], "aWQ=.MQ=="],
      [["test", 86400], "dGVzdA==.ODY0MDA="],
      [["working", 1234567890], "d29ya2luZw==.MTIzNDU2Nzg5MA=="]
    ] as [[string, number], string][])(
      "generates payload for %p",
      (params: [string, number], expected: string) => {
        // Arrange

        // Act
        const res = Token.payload(params[0], params[1])

        // Assert
        expect(res).toBe(expected)
      }
    )
  })

  describe("sign", () => {
    it.each([
      ["aWQ=.MQ==", "PNvHPV1cdk47r68wzAugWGeHfjNZOa6Su+7qj67U8ok="],
      ["dGVzdA==.ODY0MDA=", "iNsbhu5s1rdoPT960fY0Bu7sQAaaP2ysD3RJS9DQUmg="],
      [
        "d29ya2luZw==.MTIzNDU2Nzg5MA==",
        "YHdIO9UBOvAO7cTrKLJdRvE9FVuGCCVvI6bCZvtCuWE="
      ]
    ])("generates signature for %p", (payload: string, expected: string) => {
      // Arrange

      // Act
      const res = Token.sign(payload, testSecret)

      // Assert
      expect(res).toBe(expected)
    })
  })

  describe("validate", () => {
    it.each([
      ["aWQ=.MQ==.PNvHPV1cdk47r68wzAugWGeHfjNZOa6Su+7qj67U8ok=", true],
      ["dGVzdA==.ODY0MDA=.iNsbhu5s1rdoPT960fY0Bu7sQAaaP2ysD3RJS9DQUmg=", true],
      [
        "d29ya2luZw==.MTIzNDU2Nzg5MA==.YHdIO9UBOvAO7cTrKLJdRvE9FVuGCCVvI6bCZvtCuWE=",
        true
      ],
      [".invalid.invalid", false],
      ["invalid..invalid", false],
      ["invalid.invalid.", false],
      ["..", false],
      ["", false]
    ])("correctly validates %p", (token: string, expected: boolean) => {
      // Arrange

      // Act
      const res = Token.validate(token)

      // Assert
      expect(res).toBe(expected)
    })
  })

  describe("verify", () => {
    it.each([
      ["aWQ=.MQ==.PNvHPV1cdk47r68wzAugWGeHfjNZOa6Su+7qj67U8ok=", true],
      ["dGVzdA==.ODY0MDA=.iNsbhu5s1rdoPT960fY0Bu7sQAaaP2ysD3RJS9DQUmg=", true],
      [
        "d29ya2luZw==.MTIzNDU2Nzg5MA==.YHdIO9UBOvAO7cTrKLJdRvE9FVuGCCVvI6bCZvtCuWE=",
        true
      ],
      [".invalid.invalid", false],
      ["invalid..invalid", false],
      ["invalid.invalid.", false],
      ["..", false],
      ["", false]
    ])("correctly verifies %p", (token: string, expected: boolean) => {
      // Arrange

      // Act
      const res = Token.verify(token, testSecret)

      // Assert
      expect(res).toBe(expected)
    })
  })

  describe("getId", () => {
    it.each([
      ["aWQ=.is.valid", "id"],
      ["dGVzdA==.is.valid", "test"],
      ["dGVzdA==.invalid", null],
      ["dGVzdA==", null],
      ["", null]
    ])("gets id from %p", (str: string, expected: string | null) => {
      // Arrange

      // Act
      const res = Token.getId(str)

      // Assert
      expect(res).toBe(expected)
    })
  })

  describe("getTimestamp", () => {
    it.each([
      ["this.ODY0MDA=.valid", Token.epoch + 86400],
      ["yes.MQ==.valid", Token.epoch + 1],
      ["no.MQ==", null],
      ["fail", null],
      ["", null]
    ])("gets timestamp from %p", (str: string, expected: number | null) => {
      // Arrange

      // Act
      const res = Token.getTimestamp(str)

      // Assert
      expect(res).toBe(expected)
    })
  })

  describe("getSignature", () => {
    it.each([
      ["this.is.valid", "valid"],
      ["this.isnt", null],
      ["", null]
    ])("gets signature from %p", (str: string, expected: string | null) => {
      // Arrange

      // Act
      const res = Token.getSignature(str)

      // Assert
      expect(res).toBe(expected)
    })
  })

  describe("split", () => {
    it.each([
      ["this.has.dots", ["this", "has", "dots"]],
      ["this.also.has.dots", ["this", "also", "has", "dots"]],
      ["!@#.$%^", ["!@#", "$%^"]],
      ["nodots", ["nodots"]],
      ["..", ["", "", ""]],
      ["", [""]]
    ])("correctly splits %p", (str: string, expected: string[]) => {
      // Arrange

      // Act
      const res = Token.split(str)

      // Assert
      expect(res).toStrictEqual(expected)
    })
  })

  describe("toBase64", () => {
    it.each([
      ["decoded!", "ZGVjb2RlZCE="],
      ["abcdef123456", "YWJjZGVmMTIzNDU2"],
      ["!@#$%^&*()_", "IUAjJCVeJiooKV8="],
      ["", ""]
    ])("correctly converts %p", (utf8: string, expected: string) => {
      // Arrange

      // Act
      const res = Token.toBase64(utf8)

      // Assert
      expect(res).toBe(expected)
    })
  })

  describe("toUtf8", () => {
    it.each([
      ["ZGVjb2RlZCE=", "decoded!"],
      ["YWJjZGVmMTIzNDU2", "abcdef123456"],
      ["IUAjJCVeJiooKV8=", "!@#$%^&*()_"],
      ["", ""]
    ])("correctly converts %p", (base64: string, expected: string) => {
      // Arrange

      // Act
      const res = Token.toUtf8(base64)

      // Assert
      expect(res).toBe(expected)
    })
  })
})
