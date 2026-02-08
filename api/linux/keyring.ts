import { dlopen, FFIType, ptr } from 'bun:ffi'
import { pbkdf2Sync } from 'crypto'
import { infoblue } from '../../src/common/log'

const SEARCH_FLAGS = 1 | 2 | 4 

type Libsecret = ReturnType<typeof createLibsecret>

function createLibsecret() {
    return dlopen('libsecret-1.so.0', {
        secret_service_search_sync: {
            args: [FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.i32, FFIType.ptr, FFIType.ptr],
            returns: FFIType.ptr,
        },
        secret_item_get_secret: {
            args: [FFIType.ptr],
            returns: FFIType.ptr,
        },
        secret_value_get_text: {
            args: [FFIType.ptr],
            returns: FFIType.cstring,
        },
        g_hash_table_new: {
            args: [FFIType.ptr, FFIType.ptr],
            returns: FFIType.ptr,
        },
        g_hash_table_unref: {
            args: [FFIType.ptr],
            returns: FFIType.void,
        },
        g_list_free: {
            args: [FFIType.ptr],
            returns: FFIType.void,
        },
        secret_value_unref: {
            args: [FFIType.ptr],
            returns: FFIType.void,
        },
    })
}

const libc = dlopen('libc.so.6', {
    memcpy: {
        args: [FFIType.ptr, FFIType.ptr, FFIType.u64],
        returns: FFIType.ptr,
    },
})

let libsecret: Libsecret | null = null
function ensureLibraryLoaded() {
    if (!libsecret) libsecret = createLibsecret()
}

function getPointerAt(address: number): number {
    if (address === 0) return 0;
    const dest = new BigUint64Array(1);
    libc.symbols.memcpy(ptr(dest), address as any, 8);
    return Number(dest[0]);
}

export function getAllPotentialKeys(): Uint8Array[] {
    ensureLibraryLoaded()
    const keys: Uint8Array[] = []
    const salt = Buffer.from('saltysalt')
    
    const attributes = libsecret!.symbols.g_hash_table_new(null, null)
    
    // infoblue("scraping the keyring...")

    const listPtr = libsecret!.symbols.secret_service_search_sync(
        null, 
        null,
        attributes as any, 
        SEARCH_FLAGS, 
        null, 
        null
    )

    if (listPtr && (listPtr as any) !== 0) {
        let current = Number(listPtr)
        while (current !== 0) {
            const itemPtr = getPointerAt(current)
            const nextPtr = getPointerAt(current + 8)

            if (itemPtr !== 0) {
                const secretPtr = libsecret!.symbols.secret_item_get_secret(itemPtr as any)
                if (secretPtr && (secretPtr as any) !== 0) {
                    const password = libsecret!.symbols.secret_value_get_text(secretPtr as any)
                    if (password) {
                        const passStr = password.toString()
                        const derived = pbkdf2Sync(passStr, salt, 1, 16, 'sha1')
                        keys.push(new Uint8Array(derived))
                    }
                    libsecret!.symbols.secret_value_unref(secretPtr as any)
                }
            }
            current = nextPtr
        }
        libsecret!.symbols.g_list_free(listPtr as any)
    }

    libsecret!.symbols.g_hash_table_unref(attributes as any)
    
    if (keys.length === 0) {
        // infoblue("keyring empty. adding 'peanuts' fallback (standard Electron default).")
        const derived = pbkdf2Sync('peanuts', salt, 1, 16, 'sha1')
        keys.push(new Uint8Array(derived))
    }

    return keys
}