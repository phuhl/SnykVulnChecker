{-# LANGUAGE DeriveGeneric #-}

module Lib
    ( run
    ) where


import GHC.Generics
import Data.Aeson (parseJSON, eitherDecode, (.:))
import Data.Aeson.Types (parseEither, Object)
import Data.Aeson.Parser -- (decodeWith, json)
--import Data.Aeson.Internal (IResult,ifromJSON)
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
import Control.Monad (liftM2, join)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (ExceptT (..), runExceptT)
import Data.SemVer
import Data.List (zip4)
import qualified Data.Set as Set

type Dependencies =
  [(String, String)]

data Vul = Vul
  { vulTitle :: String
  , vulPackage :: String
  , vulVersion :: SemVerRange
  , vulSeverity :: String
  , vulUrl :: String
  , vulDate :: DateString
  , vulDescription :: String
  , vulOrdNum :: Int
  } deriving (Show)

instance Eq Vul where
  a == b = vulOrdNum a == vulOrdNum b
instance Ord Vul where
  a <= b = vulOrdNum a <= vulOrdNum b

vulFromRegex :: ((String, String, String, [String]), DateString, String, Int)
  -> Either String Vul
vulFromRegex ((_, _, _, (a:b:c:d:e:[])), f, g, counter) = do
  c' <- mapEitherError
    ((("Feed.xml\nTitle: " ++ a ++ "\nVersion: " ++ c) ++) . show)
    $ parseSemVerRange $ pack c
  return $ Vul a b c' d e f g counter


run :: IO ()
run = do
  feed <- parseFeedFromFile "./feed.xml"
  putStrLn "[OK] feed.xml read"
  packageJSON <- BSL.readFile "package.json"
  putStrLn "[OK] package.json read"
  res <- runExceptT $ do
    items <- liftEither
          $ case feed of
              RSSFeed (RSS.RSS _ _ channel _)
                -> Right $ rssItems channel
              _ -> Left "RSS v2 required"
    let items' = filter checkForNpm items
    liftIO $ putStrLn $ "[OK] " ++ (show $ length items')
      ++ " Vulnerabilities found in feed.xml"
    vuls <- liftEither $ mapM vulFromRegex $ zip4
               (fromTitle items')
               (fromDate items')
               (fromDescription items')
               [1..]
    liftIO $ putStrLn $ "[OK] Parsed feed.xml"
    deps <- liftEither $ parsePackageJSON packageJSON
    deps' <- liftEither
      $ mapM (mapEitherError show)
      $ map (parseSemVerRange . pack) $ snd $ unzip $ deps
    let deps'' = zip (fst $ unzip $ deps)
          $ map versionsOf deps'
    let depMatches =
          map -- dependencies
          (\(p, vs) -> (p, nubOrd $ join $ map -- versions of dependency
            (\v ->
               foldr -- vulnerabilities
               (\y a -> if matches (vulVersion y) v then
                          y : a
                        else a) [] $ filter (\z -> p == vulPackage z) vuls
            ) vs))
          deps''

    return $ filter (((<) 0) . length . snd) depMatches

  case res of
    Left e -> putStrLn $ "[ERROR] " ++ e
    Right r -> putStrLn $ "[OK] " ++ (show r)


checkForNpm :: RSSItem -> Bool
checkForNpm i = maybe False
                (\guid -> "npm:" == (take 4 $ rssGuidValue guid))
                (rssItemGuid i)

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

parsePackageJSON :: BSL.ByteString -> Either String Dependencies
parsePackageJSON packageJSON = do
  p <- eitherDecode packageJSON
  flip parseEither p $ \obj -> do
    foldl (liftM2 (++)) (return [])
      $ map (parse obj) ["dependencies", "devDependencies"]
    where parse obj fieldName = do
            dep <- obj .: (pack fieldName)
            maybe [] HM.toList <$> parseJSON dep


mapEitherError f e = case e of
  Left x -> Left $ f x
  Right x -> Right x

liftEither = ExceptT . return

nubOrd :: Ord e => [e] -> [e]
nubOrd xs = go Set.empty xs where
  go s (x:xs)
   | x `Set.member` s = go s xs
   | otherwise        = x : go (Set.insert x s) xs
  go _ _              = []
