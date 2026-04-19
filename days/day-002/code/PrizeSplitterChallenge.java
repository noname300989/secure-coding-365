// CHALLENGE: Find and fix all 3 type safety bugs in this class
// Bugs: 1) Division by zero, 2) Integer overflow, 3) ???
public class PrizeSplitterChallenge {

    public static int[] splitPrize(int totalCents, int winners) {
        int[] shares = new int[winners];
        int share = totalCents / winners;       // Bug 1: division by zero if winners == 0
        int remainder = totalCents % winners;

        for (int i = 0; i < winners; i++) {
            shares[i] = share;
        }
        shares[0] = share + remainder; // First winner gets the remainder

        return shares;
    }

    public static void main(String[] args) {
        // Test case: $25,000 among 3 winners, represented in cents
        int[] result = splitPrize(2500000, 3);
        for (int share : result) {
            System.out.printf("Winner gets: $%.2f%n", (double) share / 100);
        }

        // Edge case test — what happens here?
        int[] edge = splitPrize(2500000, 0); // Division by zero!

        // Large value test — can you spot the overflow risk?
        int bigPrize = 2_000_000_000; // $20 million in cents
        int[] big = splitPrize(bigPrize + 500_000_000, 10); // 💥 Integer overflow!
    }
}

/*
 * SOLUTION (spoilers below — try it yourself first!)
 *
 * Bug 1: Division by zero when winners == 0
 * Bug 2: Integer overflow: 2_000_000_000 + 500_000_000 overflows int before passing to method
 * Bug 3: Negative totalCents is never validated — could create negative shares
 *
 * Fix:
 *   public static long[] splitPrize(long totalCents, int winners) {
 *       if (winners <= 0) throw new IllegalArgumentException("Winners must be > 0");
 *       if (totalCents < 0) throw new IllegalArgumentException("Total must be >= 0");
 *       long[] shares = new long[winners];
 *       long share = totalCents / winners;
 *       long remainder = totalCents % winners;
 *       for (int i = 0; i < winners; i++) shares[i] = share;
 *       shares[0] = Math.addExact(share, remainder);
 *       return shares;
 *   }
 *
 * Bonus: BigDecimal not needed here since we're working in integer cents,
 *        but long is necessary to avoid overflow for large prize pools.
 */
