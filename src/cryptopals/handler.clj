(ns cryptopals.handler
  (:use compojure.core)
  (:require [compojure.handler :as handler]
            [cryptopals.hmac :refer [hmac]]
            [cryptopals.sha1 :refer [sha1]]
            [cryptopals.utils :refer :all]))

(def ^:private private-key (.getBytes "YELLOW SUBMARINE"))

(defn insecure-compare [ms xs ys]
  (loop [x xs y ys]
    (if (and (nil? (first x)) (nil? (first y)))
      true
      (do (Thread/sleep ms)
          (if (= (first x) (first y))
            (recur (rest x) (rest y))
            false)))))

(defn verify [file signature]
  (let [f (.getBytes file)
        s (hex-decode signature)]
        (insecure-compare 5 [0 5 3 18] s)
                                        ;        (insecure-compare 1 (hmac sha1 private-key f) s)
        ))

(defroutes main-routes
  (GET "/test" [file signature]
       (if (verify file signature)
         {:status 200}
         {:status 500})))

(def app (handler/api main-routes))
