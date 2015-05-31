(ns cryptopals.challenges.set4
  (:require [cryptopals.utils :refer :all]
            [cryptopals.block :refer :all]
            [cryptopals.stream :refer :all]))

(defn challenge-25
  "Break random access read/write AES CTR"
  []
  (let [msg (-> (slurp "resources/7.txt")
                (clojure.string/split-lines)
                (clojure.string/join)
                (b64-decode)
                (byte-array)
                (decrypt-ecb (.getBytes "YELLOW SUBMARINE"))
                ((partial take 500)))
        key (rand-byte-array 16)
        nonce 0
        cipher (ctr-encrypt msg key nonce)
        edit-fn (fn [cipher offset text]
                  (ctr-edit cipher key nonce offset text))]
    (bytes->str (break-ctr cipher edit-fn))))

(defn challenge-26
  "CTR bitflipping"
  []
   (let [prefix "comment1=cooking%20MCs;userdata="
         suffix ";comment2=%20like%20a%20pound%20of%20bacon"
         key (rand-byte-array 16)
         enc-fn (fn [arg]
                  (ctr-encrypt (concat
                                prefix
                                (clojure.string/escape (apply str arg) {\= "" \; ""})
                                suffix) key 0))
         decrypt-fn (fn [cipher] (ctr-encrypt cipher key 0))
         valid? (partial admin? decrypt-fn ";" "=")]
     (valid? (bitflip-ctr enc-fn "foo;admin=true"))))

(defn challenge-27
  "Recover the key from CBC with IV=Key"
  []
    (let [prefix "comment1=cooking%20MCs;userdata="
          suffix ";comment2=%20like%20a%20pound%20of%20bacon"
          key (rand-byte-array 16)
          enc-fn (fn [arg]
                   (-> (concat
                        prefix
                        (clojure.string/escape (apply str arg) {\= "" \; ""})
                        suffix)
                       (pkcs7 16)
                       (encrypt-cbc key key)))
          decrypt-fn (fn [cipher]
                       (rm-pkcs7 (decrypt-cbc (byte-array cipher) key key)))
          valid? (fn [x] (let [msg (decrypt-fn x)]
                           (try (doall (map char msg))
                                (catch Exception e (throw (Exception. (bytes->str msg)))))))]

      (let [c (#(concat (take 16 %) (repeat 16 0) (take 16 %) (drop 48 %)) (enc-fn (repeat 48 \A)))
            k (try (valid? c)
                   (catch Exception e (#(byte-array-xor (take 16 %) (take 16 (drop 32 %)))
                                       (.getMessage e))))]
        {:res (map int k) :org-key (map int key)})))
