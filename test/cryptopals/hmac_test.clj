(ns cryptopals.hmac-test
  (:require [clojure.test :refer :all]
            [cryptopals.hmac :refer :all]
            [cryptopals.sha1 :refer [sha1]]
            [cryptopals.utils :refer [bytes->hex]]))

(deftest hmac-test
  (testing "hmac(\"\", \"\")"
    (let [k (.getBytes "")
          m k]
      (is (= "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d" (bytes->hex (hmac sha1 k m))))))
  (testing "hmac(\"key\", \"The quick brown fox jumps over the lazy dog\"")
  (let [k (.getBytes "key")
        m (.getBytes "The quick brown fox jumps over the lazy dog")]
    (is (= "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9" (bytes->hex (hmac sha1 k m))))))
