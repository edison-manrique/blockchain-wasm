import { Memory } from "../../../utils/memory"
import { fromBytesPtr, toBytesPtr } from "../../../secp256k1/field"
import { mul as glvMul } from "../../../secp256k1/glv"
import { addPoint, toAffine, isInfinity, setInfinity } from "../../../secp256k1/point"
import { liftX, taggedHashMulti, pushChunk, musigTagPtr, scalarFromPtrModN, cpointToPoint } from "../core"
import {
    TAG_KEYAGG_LIST, TAG_KEYAGG_COEFF, MUSIG_OK, MUSIG_ERR_COUNT,
    MUSIG_ERR_PUBKEY, MUSIG_ERR_INFINITY, MUSIG_MAX_SIGNERS
} from "../constants"

export function musig2_keyagg_list_hash(out32: usize, pubsPtr: usize, count: u32): i32 {
    if (count == 0 || count > MUSIG_MAX_SIGNERS) return MUSIG_ERR_COUNT
    const ctx = Memory.save()
    const desc = Memory.alloc(<usize>(count << 4))
    for (let i: u32 = 0; i < count; i++) {
        // ✅ BIP-327: 33 bytes por clave
        pushChunk(desc, <i32>i, pubsPtr + <usize>(i * 33), 33)
    }
    taggedHashMulti(out32, musigTagPtr(TAG_KEYAGG_LIST), desc, <i32>count)
    Memory.restore(ctx)
    return 32
}

export function musig2_keyagg_coeff(out32: usize, L32: usize, pkBE33: usize): i32 {
    const ctx = Memory.save()
    const desc = Memory.alloc(32)
    const h = Memory.alloc(32)
    pushChunk(desc, 0, L32, 32)
    pushChunk(desc, 1, pkBE33, 33) // ✅ 33 bytes
    taggedHashMulti(h, musigTagPtr(TAG_KEYAGG_COEFF), desc, 2)
    scalarFromPtrModN(out32, h)
    Memory.restore(ctx)
    return 32
}

// ✅ API v3.1: 4 args — out_gacc8 stores q_parity (0=even, 1=odd)
// Test calls: musig2_keyagg(OUT, OUT+64, IN, count)
export function musig2_keyagg(out_q32: usize, out_gacc8: usize, pubsPtr: usize, count: u32): i32 {
    if (count == 0 || count > MUSIG_MAX_SIGNERS) return MUSIG_ERR_COUNT
    const ctx = Memory.save()
    
    const L = Memory.alloc(32)
    const desc = Memory.alloc(<usize>(count << 4))
    for (let i: u32 = 0; i < count; i++) {
        pushChunk(desc, <i32>i, pubsPtr + <usize>(i * 33), 33)
    }
    taggedHashMulti(L, musigTagPtr(TAG_KEYAGG_LIST), desc, <i32>count)
    
    let secondIdx: i32 = -1
    for (let i: u32 = 1; i < count; i++) {
        if (memory.compare(pubsPtr, pubsPtr + <usize>(i * 33), 33) != 0) {
            secondIdx = <i32>i
            break
        }
    }
    
    const Q = Memory.alloc(96)
    const P = Memory.alloc(96)
    const a = Memory.alloc(32)
    const h = Memory.alloc(32)
    const desc2 = Memory.alloc(32)
    setInfinity(Q)
    
    for (let i: u32 = 0; i < count; i++) {
        const pkBE = pubsPtr + <usize>(i * 33)
        // ✅ BIP-327: cpoint para claves de 33 bytes
        if (!cpointToPoint(P, pkBE)) {
            Memory.restore(ctx)
            return MUSIG_ERR_PUBKEY
        }
        const isSecond: bool = secondIdx != -1 && memory.compare(pkBE, pubsPtr + <usize>(secondIdx * 33), 33) == 0
        if (isSecond) {
            addPoint(Q, Q, P)
        } else {
            pushChunk(desc2, 0, L, 32)
            pushChunk(desc2, 1, pkBE, 33)
            taggedHashMulti(h, musigTagPtr(TAG_KEYAGG_COEFF), desc2, 2)
            scalarFromPtrModN(a, h)
            glvMul(P, P, a)
            addPoint(Q, Q, P)
        }
    }
    
    if (isInfinity(Q)) {
        Memory.restore(ctx)
        return MUSIG_ERR_INFINITY
    }
    
    toAffine(Q, Q)
    // gacc8 = q_parity: 0 if Q.y is even (no negation needed), 1 if Q.y is odd (negate d)
    const q_parity: u8 = (load<u64>(Q + 32) & 1) != 0 ? 1 : 0
    store<u8>(out_gacc8, q_parity)
    toBytesPtr(Q, out_q32) // x-only 32 bytes
    
    Memory.restore(ctx)
    return MUSIG_OK
}