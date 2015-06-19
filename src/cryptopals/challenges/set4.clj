(ns cryptopals.challenges.set4
  (:require [cryptopals.utils :refer :all]
            [cryptopals.block :refer :all]
            [cryptopals.stream :refer :all]
            [cryptopals.sha1 :refer :all]))

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

(defn challenge-28
  "Implement a SHA-1 keyed MAC"
  []
  (let [key "yellow submarine"
        mac-fn (fn [msg] (sha1 (concat key msg)))
        auth-fn (fn [msg mac]
                  (= (mac (sha1 (concat key msg)))))]))

(defn challenge-29
  "Break a SHA-1 keyed MAC using length extension"
  []
  (let [key "yellow submarine"
        prefix "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
        auth-fn (fn [msg mac] (= mac (sha1 (concat key msg))))
        mac (sha1 (concat key prefix))]
    (let [arg ";admin=true"
          len (count prefix)]
      (loop [kl 0]
        (let [m (map byte (concat (sha1-pad (+ kl len)) arg))
              nmac (sha1-extend arg mac (+ (count m) kl len))]
          (if (auth-fn (concat prefix m) nmac)
            {:msg (bytes->str m) :mac nmac :omac mac}
            (recur (inc kl))))))))

(defn challenge-30
  "Break an MD4 keyed MAC using length extension"
  [])

(defn challlenge-31
  "Implement and break HMAC-SHA1 with an artificial timing leak"
  [])
