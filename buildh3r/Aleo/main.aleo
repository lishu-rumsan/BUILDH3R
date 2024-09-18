program lishu_auction.aleo {
    record Bid {
        owner: address,
        bidder: address,
        amount: u64,
        is_winner: bool,
    }

    record Prize {
        owner: address,
        amount: u64,
    }

    transition place_bid(bidder: address, amount: u64) -> Bid {
        // Ensure the caller is the auction bidder.
        assert_eq(self.caller, bidder);
        // Return a new 'Bid' record for the auction bidder.
        return Bid {
            owner: aleo1f9rwrqkpng27xmuf630xuup479mcyl6etnzwu74v3329jg06zcxq7wktzl,
            bidder: bidder,
            amount: amount,
            is_winner: false,
        };
    }

    transition resolve(first: Bid, second: Bid) -> Bid {
        // Ensure the caller is the auctioneer.
        assert_eq(self.caller, aleo1f9rwrqkpng27xmuf630xuup479mcyl6etnzwu74v3329jg06zcxq7wktzl);
        // Resolve the winner of the auction.
        if (first.amount >= second.amount) {
            return first;
        } else {
            return second;
        }
    }

    transition finish(bid: Bid) -> Bid {
        // Ensure the caller is the auctioneer.
        assert_eq(self.caller, aleo1f9rwrqkpng27xmuf630xuup479mcyl6etnzwu74v3329jg06zcxq7wktzl);
        // Return 'is_winner' as 'true' in the winning 'Bid'.
        return Bid {
            owner: bid.bidder,
            bidder: bid.bidder,
            amount: bid.amount,
            is_winner: true,
        };
    }

    transition claim(bid: Bid) -> Prize {
        assert_eq(bid.is_winner, true);
        return Prize {
            owner: bid.bidder,
            amount: bid.amount,
        };
    }
}