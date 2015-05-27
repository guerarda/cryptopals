(ns cryptopals.challenges.set1
  (:require [cryptopals.utils :refer :all]
            [cryptopals.block :refer :all]
            ))

(defn challenge-1
  "Convert hex to base64"
  []
  (let [hex "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        base64 "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"]
    (if (= (map int (hex-decode hex)) (map int (b64-decode base64)))
      (apply str (map char (b64-decode base64)))
      "false")))

(defn challenge-2
  "Fixed XOR"
  []
  (let [s1 "1c0111001f010100061a024b53535009181c"
        s2 "686974207468652062756c6c277320657965"
        r "746865206b696420646f6e277420706c6179"]
    (if (= (hex-decode r) (map bit-xor (hex-decode s1) (hex-decode s2)))
      "pass"
      "fail")))

(defn challenge-3
  "Single-byte XOR cipher"
  []
  (let [cipher (hex-decode "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")]
    (first (break-byte-xor cipher))))

(defn challenge-4
  "Detect single-character XOR"
  []
  (let [ciphers (map hex-decode (clojure.string/split-lines (slurp "resources/4.txt")))]
    (first (sort-by :score < (pmap (comp first break-byte-xor) ciphers)))))

(defn challenge-5
  "Implement repeating-key XOR"
  []
  (let [key (.getBytes "ICE")
        s1 (.getBytes "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
        r1 "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"]
    (if (= (repeat-xor s1 (map int key)) (hex-decode r1))
      "pass"
      "fail")))

(defn challenge-6
  "Break repeating-key XOR"
  []
  (let [cipher (-> (slurp "resources/6.txt")
                   (clojure.string/split-lines)
                   (clojure.string/join)
                   (b64-decode))]
    (let [ks (:keysize (first (keysize-guess cipher 8 50)))
          key (break-repeat-xor cipher ks)]
      (hash-map :key (bytes->str key) :message (bytes->str (repeat-xor cipher (map int key)))))))

(defn challenge-7
  "AES in ECB mode"
  []
  (let [cipher (-> (slurp "resources/7.txt")
                   (clojure.string/split-lines)
                   (clojure.string/join)
                   (b64-decode))
        key (.getBytes "YELLOW SUBMARINE")]
    (bytes->str (decrypt-ecb cipher key))))

(defn challenge-8
  "Detect AES in ECB mode"
  []
  (let [ciphers (->> (slurp "resources/8.txt")
                     (clojure.string/split-lines)
                     (map hex-decode))]
    (apply detect-ecb 16 ciphers)))
