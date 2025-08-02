// 从 Deno 标准库导入必要的模块
import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { toHashString } from "https://deno.land/std@0.224.0/crypto/to_hash_string.ts";

// Google API 的主机地址
const GOOGLE_API_HOST = "https://generativelanguage.googleapis.com";

/**
 * 内存存储，用于记录每个 API 密钥组的轮询状态。
 * - Key: API 密钥列表的 SHA-256 哈希值。
 * - Value: 下一个要使用的密钥的索引。
 */
const rotationState = new Map<string, number>();


// --- 辅助函数 ---

/**
 * 为给定的字符串创建一个 SHA-256 哈希值。
 * @param text 要哈希的文本。
 * @returns 返回一个 Promise，解析为十六进制编码的哈希字符串。
 */
async function sha256(text: string): Promise<string> {
    const hashBuffer = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(text),
    );
    return toHashString(hashBuffer);
}

/**
 * 解析 <roleInfo> 标签并返回一个角色映射对象。
 */
function parseRoleInfo(text: string): { [key: string]: string } {
    const roleInfoMatch = text.match(/<roleInfo>
