(ns cryptopals.challenges.set2
  (:require [cryptopals.utils :refer :all]
            [cryptopals.block :refer :all]))

(defn challenge-9
  "Implement PKCS#7 padding"
  []
  (let [arg "YELLOW SUBMARINE"]
    (pkcs7 (.getBytes arg) 20)))

(defn challenge-10
  "Implement CBC mode"
  []
  (let [cipher (-> (slurp "resources/10.txt")
                   (clojure.string/split-lines)
                   (clojure.string/join)
                   (b64-decode))
        key (.getBytes "YELLOW SUBMARINE")
        iv (repeat 16 0)]
    (bytes->str (decrypt-cbc cipher key iv))))

(defn challenge-11
  "An ECB/CBC detection oracle"
  []
  (let [message "This is a scret message"]
    (detect-mode (encryption-oracle (.getBytes message)))))

(defn challenge-12
  "Byte-at-a-time ECB decryption (Simple)"
  []
  (let [msg "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
        key (rand-byte-array 16)
        oracle-fn (fn [x] (-> (mapv int x)
                              (into (b64-decode msg))
                              (pkcs7 16)
                              (byte-array)
                              (encrypt-ecb key)
                              ))]
    (ecb-break-message oracle-fn 16)))

(defn challenge-13
  "ECB cut-and-paste"
  []
  (let [profile-fn (fn [x] {:email (clojure.string/escape x {\= "" \& ""})
                            :uid 10
                            :role "user"})
        encode-fn (fn [x] (subs (reduce-kv #(str %1 "&" (name %2) "=" %3) nil x) 1))
        key (rand-byte-array 16)
        encrypt-profile (fn [x] (-> (profile-fn x)
                                    (encode-fn)
                                    (pkcs7 16)
                                    (byte-array)
                                    (encrypt-ecb key)))
        decrypt-profile (fn [x] (-> (decrypt-ecb x key)
                                    (rm-pkcs7)
                                    (bytes->str)
                                    (parse-kv \& \=)))]
    (let [email "foo@gmail.com"
          user-blocks (take 2 (partition 16 (encrypt-profile email)))
          admin-block (->> (.getBytes "admin")
                           (#(pkcs7 % 16))
                           (bytes->str)
                           (str (apply str (repeat 10 \a)))
                           (encrypt-profile)
                           (partition 16)
                           (second)
                           )
          cipher (byte-array (flatten (concat user-blocks admin-block)))]
      (:role (decrypt-profile cipher)))))

(defn challenge-14
  "Byte-at-a-time ECB decryption (Harder)"
  []
  (let [msg "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
        key (rand-byte-array 16)
        prefix (rand-byte-array (rand-int 256))
        oracle-fn (fn [x] (-> (concat prefix x (b64-decode msg))
                              (pkcs7 16)
                              (byte-array)
                              (encrypt-ecb key)))]
    (ecb-break-message oracle-fn 16)))

(defn challenge-15
  "PKCS#7 padding validation"
  []
  (let [str-a "ICE ICE BABY"
        str-b "ICE ICE BABY"
        str-c "ICE ICE BABY"]
    (try (prn (apply str (rm-pkcs7 str-a)))
         (prn (apply str (rm-pkcs7 str-b)))
         (prn (apply str (rm-pkcs7 str-c)))
         (catch Exception e (str "Caught:" (.getMessage e))))))

(defn challenge-16
  "CBC bitflipping attacks"
  []
  (let [prefix "comment1=cooking%20MCs;userdata="
        suffix ";comment2=%20like%20a%20pound%20of%20bacon"
        key (rand-byte-array 16)
        oracle-fn (fn [x] (-> (concat prefix (clojure.string/escape (apply str x) {\= "" \; ""}) suffix)
                              (pkcs7 16)
                              (encrypt-cbc key (repeat 0))))
        decrypt-fn #(decrypt-cbc % key (repeat 0))
        valid-fn (partial admin? decrypt-fn \; \=)]
    (cbc-bitflip oracle-fn valid-fn 16 ";admin=true")))
