{-# LANGUAGE DeriveGeneric #-}

module Lib
    ( run
    ) where


import GHC.Generics
import Data.Aeson (parseJSON, eitherDecode, (.:))
import Data.Aeson.Types (parseMaybe, Object)
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
import System.Environment (getArgs)

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
  cmdArgs <- getArgs
  res <- runExceptT $ do
    (feedP, packageP) <- liftEither
      $ if length cmdArgs == 2 then
          Right (cmdArgs !! 0, cmdArgs !! 1)
        else
          Left "\n\nUsage: SnykVulnChecker <path to feed.xml> <path to package.json>"
    feed <- liftIO $ parseFeedFromFile feedP
    liftIO $ putStrLn $ "[OK] " ++ feedP ++ " read"
    packageJSON <- liftIO $ BSL.readFile packageP
    liftIO $ putStrLn $ "[OK] " ++ packageP ++ " read"

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
    let deps'' = zip3 (fst $ unzip $ deps)
                 (snd $ unzip $ deps)
                 $ map versionsOf deps'
    let depMatches =
          filter (((<) 0) . length . thd)
          $ map -- dependencies
          (\(p, v1, vs) -> (p, v1, nubOrd $ join $ map -- versions of dependency
            (\v ->
               foldr -- vulnerabilities
               (\y a -> if matches (vulVersion y) v then
                          y : a
                        else a) [] $ filter (\z -> p == vulPackage z) vuls
            ) vs))
          deps''

    return $ depMatches

  case res of
    Left e -> putStrLn $ "[ERROR] " ++ e
    Right rs -> do
      putStrLn $ "\n\n[RESULT] Found "
        ++ (show $ count) ++ " Vulnerabilit"
        ++ (if count == 1 then "y" else "ies") ++ ":\n"
      mapM (\(p, ver, vs) ->
              mapM (\v -> do
                       putStrLn $ "Packet " ++ p ++ " (Version: " ++ ver ++ ")"
                         ++ " vulnerable to:\n" ++ vulTitle v
                       putStrLn $ "Severity: " ++ vulSeverity v
                       putStrLn $ "Vulnerable versions: " ++ (show $ vulVersion v)
                       putStrLn $ "Found on: " ++ (show $ vulDate v)
                       putStrLn $ "See more at: " ++ vulUrl v
                       putStrLn "")
              vs)
        rs
      return ()
        where count = length $ join $ map (thd) rs


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
  let dep = fromMaybe [] $ parse p "dependencies"
  let depDev = fromMaybe [] $ parse p "devDependencies"
  let deps = dep ++ depDev
  if length deps == 0 then Left "No dependencies found"
    else Right deps
  where parse p fieldName =
          flip parseMaybe p $ \obj -> do
            dep <- obj .: (pack fieldName)
            maybe [] HM.toList <$> parseJSON dep
        fromMaybe _ (Just x) = x
        fromMaybe d _ = d
--, "devDependencies"]

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

thd = \(_, _, x) -> x
