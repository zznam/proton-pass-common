import { describe, expect, test } from "bun:test";

import { mime_type_from_content, mime_type_from_content_head_tail } from "./pkg/ui";

const TEST_DATA_DIR = new URL("../../proton-pass-common/test_data/file_format", import.meta.url).pathname;

async function readTestFile(filename: string): Promise<Uint8Array> {
    const filePath = `${TEST_DATA_DIR}/${filename}`;
    const buffer = await Bun.file(filePath).arrayBuffer();
    return new Uint8Array(buffer);
}

describe("ProtonPassWeb FileType detection", () => {
    test("Can detect image", async () => {
        const fileBytes = await readTestFile("sample.jpg");

        const result = mime_type_from_content(fileBytes);

        expect(result).toBeDefined();
        expect(result).toBe("image/jpeg");
    });

    test("Can detect type in big file", async () => {
        const fileBytes = await readTestFile("sample-big.xlsx");

        // First 1.4MB
        const head = fileBytes.slice(0, 1_468_000);

        // Last 128kb
        const tail = fileBytes.slice(fileBytes.length - 128_000);

        const result = mime_type_from_content_head_tail(head, tail, BigInt(fileBytes.length));

        expect(result).toBeDefined();
        expect(result).toBe("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    });
});