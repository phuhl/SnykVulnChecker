{-# LANGUAGE DeriveGeneric #-}

module Lib
    ( run
    ) where


import GHC.Generics
import Data.Aeson -- (parseJSON, fromJSON, Value, Result, ToJSONKey)
import Data.Aeson.Types
import Data.Aeson.Parser -- (decodeWith, json)
import Data.Aeson.Internal (IResult,ifromJSON)
import Text.Feed.Import (parseFeedFromFile)
import qualified Data.HashMap.Strict as HM
import Text.Feed.Types (Feed (RSSFeed))
import Text.RSS.Syntax as RSS
import Text.Regex.PCRE ((=~))
import HTMLEntities.Decoder (htmlEncodedText)
import Data.Text.Lazy.Builder (toLazyText)
import Data.Text (pack)
import Data.Text.Lazy (unpack)
import qualified Data.ByteString.Lazy as BSL
import Data.Either.Utils
import Control.Monad.IO.Class
import Control.Monad.Trans.Except


type Dependencies =
  [(String, String)]

data Vul = Vul
  { vulTitle :: String
  , vulPackage :: String
  , vulVersion :: String
  , vulSeverity :: String
  , vulUrl :: String
  , vulDate :: DateString
  , vulDescription :: String
  } deriving (Show)

run :: IO ()
run = do
  feed <- parseFeedFromFile "./feed.xml"
  putStrLn "[OK] feed.xml read"
  packageJSON <- BSL.readFile "package.json"
  putStrLn "[OK] package.json read"
  res <- runExceptT $ do
    let allItems = case feed of
          RSSFeed (RSS.RSS _ _ channel _) -> rssItems channel
    let items = filter checkForNpm allItems
    liftIO $ putStrLn
      $ "[OK] " ++ (show $ length items) ++ " Vulnerabilities found in feed.xml"
    let vuls = map fromRegex
               $ zip3 (fromTitle items) (fromDate items) (fromDescription items) :: [Vul]
    liftIO $ putStrLn $ "[OK] Parsed feed.xml"
    r <- ExceptT $ return $ eitherDecode packageJSON
    let lrDeps = parsePackageJSON r
    deps <- ExceptT $ return $ lrDeps

    return deps

  case res of
    Left e -> putStrLn $ "[ERROR] " ++ e
    Right r -> putStrLn $ "[OK] " ++ (show r)


checkForNpm :: RSSItem -> Bool
checkForNpm i = maybe False
                (\guid -> "npm:" == (take 4 $ rssGuidValue guid))
                (rssItemGuid i)

fromRegex :: ((String, String, String, [String]), DateString, String) -> Vul
fromRegex ((_, _, _, (a:b:c:d:e:[])), f, g) = Vul a b c d e f g


fromTitle = map (\t -> t =~ "^(.*)\\sfor\\s(.*)\\s(.*)\\swith\\s(medium|high|low)\\sseverity\\s(.*)$")
            . map (replaceSpace)
            . map (unpack . toLazyText . htmlEncodedText . pack)
            . map (unpack . toLazyText . htmlEncodedText . pack)
            . map (maybe "" id)
            . map rssItemTitle
              where
                replaceSpace = map (\s -> if s == '\160' then ' ' else s)

fromDate = map (maybe "" id)
           . map rssItemPubDate
fromDescription = map (maybe "" id)
                  . map rssItemDescription

parsePackageJSON :: Object -> Either String Dependencies
parsePackageJSON p = do
  flip parseEither p $ \obj -> do
    dep <- obj .: (pack "dependencies")
    maybe [] HM.toList <$> parseJSON dep


liftEither :: Either a b -> Either (IO a) (IO b)
liftEither (Left a) = Left $ return a
liftEither (Right a) = Right $ return a

liftLeft :: Either a b -> Either (IO a) b
liftLeft (Left a) = Left $ return a
liftLeft (Right a) = Right a

liftRight :: Either a b -> Either a (IO b)
liftRight (Right a) = Right $ return a
liftRight (Left a) = Left a
