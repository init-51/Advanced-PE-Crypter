/* appended PE to rdi is encrypted.
 * only PE header is decrypted, then copy all segments
 * to required virtual address, decrypt and change protection.
 * then transfer control to entry point.
 */

/* import table can be copied to heap, decrypted and resolved
 * assuming it is at correct virtual address (by using right
 * calculations). this way we can avoid rop gadgets. 
 * then copy it to correct virtual address.
 */

/* to avoid HeapAlloc, import table virtual size would be prepended
 * to rdi file.
 */