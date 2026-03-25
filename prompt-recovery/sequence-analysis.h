#ifndef SEQUENCE_ANALYSIS_H
#define SEQUENCE_ANALYSIS_H

#ifndef __cplusplus
#error
#endif

#include <vector>
#include <optional>
#include <algorithm>

// Type aliases for convenience
using ScoreMatrix = std::vector<std::vector<int>>;

// Function to compute score between two uint64_t values
template<typename T>
static int needleman_wunsch_score(const T& a, const T& b) {
    return (a == b) ? 2 : -1;  // Example: +2 match, -1 mismatch
}

// Needleman-Wunsch algorithm for uint64_t sequences
template <typename T>
struct AlignmentResult {
    std::vector<std::optional<T>> aligned_seq1;
    std::vector<std::optional<T>> aligned_seq2;
    std::vector<std::optional<size_t>> seq1_to_seq2;
    std::vector<std::optional<size_t>> seq2_to_seq1;
    int score{};
};

template <typename T>
static AlignmentResult<T> needleman_wunsch(const std::vector<T> &seq1, const std::vector<T> &seq2, int gap_penalty) {
    size_t n = seq1.size();
    size_t m = seq2.size();

    // Initialize DP and traceback matrices
    ScoreMatrix dp(n+1, std::vector<int>(m+1, 0));
    std::vector<std::vector<char>> tb(n+1, std::vector<char>(m+1, ' ')); // 'D'=diag, 'U'=up, 'L'=left

    // Initialize first row and column
    for (size_t i = 1; i <= n; ++i) {
        dp[i][0] = dp[i-1][0] + gap_penalty;
        tb[i][0] = 'U';
    }
    for (size_t j = 1; j <= m; ++j) {
        dp[0][j] = dp[0][j-1] + gap_penalty;
        tb[0][j] = 'L';
    }

    // Fill DP table
    for (size_t i = 1; i <= n; ++i) {
        for (size_t j = 1; j <= m; ++j) {
            int match = dp[i-1][j-1] + needleman_wunsch_score(seq1[i-1], seq2[j-1]);
            int delete_ = dp[i-1][j] + gap_penalty;
            int insert_ = dp[i][j-1] + gap_penalty;
            dp[i][j] = std::max({match, delete_, insert_});
            if (dp[i][j] == match) tb[i][j] = 'D';
            else if (dp[i][j] == delete_) tb[i][j] = 'U';
            else tb[i][j] = 'L';
        }
    }

    // Traceback
    size_t i = n, j = m;
    std::vector<std::optional<T>> aln1_rev;
    std::vector<std::optional<T>> aln2_rev;
    std::vector<std::optional<size_t>> seq1_to_seq2(n, std::nullopt);
    std::vector<std::optional<size_t>> seq2_to_seq1(m, std::nullopt);

    while (i > 0 || j > 0) {
        if (i > 0 && j > 0 && tb[i][j] == 'D') {
            aln1_rev.push_back(seq1[i-1]);
            aln2_rev.push_back(seq2[j-1]);
            seq1_to_seq2[i-1] = j-1;
            seq2_to_seq1[j-1] = i-1;
            --i; --j;
        } else if (i > 0 && tb[i][j] == 'U') {
            aln1_rev.push_back(seq1[i-1]);
            aln2_rev.push_back(std::nullopt);
            --i;
        } else { // 'L'
            aln1_rev.push_back(std::nullopt);
            aln2_rev.push_back(seq2[j-1]);
            --j;
        }
    }

    // Reverse sequences
    std::reverse(aln1_rev.begin(), aln1_rev.end());
    std::reverse(aln2_rev.begin(), aln2_rev.end());

    return {aln1_rev, aln2_rev, seq1_to_seq2, seq2_to_seq1, dp[n][m]};
}

template <typename T>
std::size_t levenshtein_distance(const std::vector<T>& v1, const std::vector<T>& v2) {
    const std::size_t m = v1.size();
    const std::size_t n = v2.size();

    if (m == 0)
        return n;
    if (n == 0)
        return m;

    std::vector<std::size_t> prev_row(n + 1);
    std::vector<std::size_t> curr_row(n + 1);

    // Initialize first row
    for (std::size_t j = 0; j <= n; ++j)
        prev_row[j] = j;

    for (std::size_t i = 1; i <= m; ++i) {
        curr_row[0] = i;
        for (std::size_t j = 1; j <= n; ++j) {
            std::size_t cost = (v1[i - 1] == v2[j - 1]) ? 0 : 1;
            curr_row[j] = std::min({
                prev_row[j] + 1,      // deletion
                curr_row[j - 1] + 1,  // insertion
                prev_row[j - 1] + cost // substitution
            });
        }
        prev_row.swap(curr_row);
    }

    return prev_row[n];
}

// Levenshtein distance normalized by the maximum length of the inputs -> similarity measure between 0 (completely different) and 1 (identical)
template <typename T>
double levenshtein_similarity(const std::vector<T>& v1, const std::vector<T>& v2) {
    if (v1.empty() && v2.empty())
        return 1.0; // identical empty vectors

    auto dist = levenshtein_distance(v1, v2);
    auto max_len = std::max(v1.size(), v2.size());

    return 1.0 - static_cast<double>(dist) / static_cast<double>(max_len);
}

#endif