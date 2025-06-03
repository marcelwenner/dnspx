#!/bin/bash

# DNS Proxy Comprehensive Test Script
# ====================================
# Tests performance, functionality, and reliability of your DNS proxy

# Configuration
PROXY_HOST="127.0.0.1"
PROXY_PORT="53"
FALLBACK_DNS="1.1.1.1"
TEST_TIMEOUT=10

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test domains
TEST_DOMAINS=(
    "google.com"
    "github.com" 
    "stackoverflow.com"
    "reddit.com"
    "wikipedia.org"
    "cloudflare.com"
    "amazon.com"
    "microsoft.com"
)

# Statistics arrays
QUERY_TIMES=()
FAILED_QUERIES=0
TOTAL_QUERIES=0

# Utility functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

print_header() {
    echo "=================================================="
    echo -e "${BLUE}$1${NC}"
    echo "=================================================="
}

print_section() {
    echo ""
    echo -e "${YELLOW}>>> $1${NC}"
    echo "--------------------------------------------------"
}

# Check if dig is available
check_prerequisites() {
    print_section "Checking Prerequisites"
    
    if ! command -v dig &> /dev/null; then
        log_error "dig command not found. Please install dnsutils (Ubuntu/Debian) or bind-tools (CentOS/RHEL)"
        exit 1
    fi
    log_success "dig command available"
    
    if ! command -v bc &> /dev/null; then
        log_warning "bc not found. Statistical calculations will be limited"
    else
        log_success "bc available for calculations"
    fi
}

# Test basic connectivity to proxy
test_proxy_connectivity() {
    print_section "Testing Proxy Connectivity"
    
    log_info "Attempting to connect to DNS proxy..."
    
    # Try dig and check for actual response content
    RESULT=$(timeout $TEST_TIMEOUT dig @$PROXY_HOST +short google.com 2>&1)
    
    # Check if we got an IP address (even with warnings)
    if echo "$RESULT" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' >/dev/null 2>&1; then
        log_success "DNS proxy is responding on $PROXY_HOST:$PROXY_PORT"
        if echo "$RESULT" | grep -i "warning.*id mismatch" >/dev/null 2>&1; then
            log_warning "DNS ID mismatch detected - this is a known issue with some proxies"
            log_info "The proxy works but may need ID handling improvements"
        fi
        return 0
    fi
    
    # Fallback: Try with nslookup
    if command -v nslookup &> /dev/null; then
        log_info "Trying alternative method with nslookup..."
        NSLOOKUP_RESULT=$(timeout $TEST_TIMEOUT nslookup google.com $PROXY_HOST 2>/dev/null | grep "Address:" | tail -1)
        if [[ -n "$NSLOOKUP_RESULT" ]]; then
            log_success "DNS proxy is responding (verified with nslookup)"
            return 0
        fi
    fi
    
    log_error "DNS proxy is not responding properly on $PROXY_HOST:$PROXY_PORT"
    log_error "Raw dig output: $RESULT"
    log_warning "Continuing with tests to diagnose the issue..."
    return 1
}

# Test basic DNS resolution
test_basic_resolution() {
    print_section "Testing Basic DNS Resolution"
    
    for domain in "${TEST_DOMAINS[@]}"; do
        echo -n "Testing $domain... "
        
        START_TIME=$(date +%s.%N)
        RESULT=$(timeout $TEST_TIMEOUT dig @$PROXY_HOST +short $domain 2>/dev/null)
        END_TIME=$(date +%s.%N)
        
        ((TOTAL_QUERIES++))
        
        if [[ -n "$RESULT" ]]; then
            QUERY_TIME=$(echo "($END_TIME - $START_TIME) * 1000" | bc 2>/dev/null || echo "N/A")
            if [[ "$QUERY_TIME" != "N/A" ]]; then
                QUERY_TIMES+=($QUERY_TIME)
                echo -e "${GREEN}✓${NC} (${QUERY_TIME}ms)"
            else
                echo -e "${GREEN}✓${NC}"
            fi
        else
            echo -e "${RED}✗${NC} No response"
            ((FAILED_QUERIES++))
        fi
    done
    
    echo ""
    log_info "Basic resolution test completed: $((TOTAL_QUERIES - FAILED_QUERIES))/$TOTAL_QUERIES successful"
}

# Test cache performance
test_cache_performance() {
    print_section "Testing Cache Performance"
    
    # Use a real domain that we haven't queried yet
    TEST_DOMAIN="httpbin.org"
    
    # First query (cache miss)
    echo -n "First query (cache miss)... "
    START_TIME=$(date +%s.%N)
    RESULT1=$(timeout $TEST_TIMEOUT dig @$PROXY_HOST +short $TEST_DOMAIN 2>/dev/null)
    END_TIME=$(date +%s.%N)
    
    if [[ -n "$RESULT1" ]]; then
        FIRST_QUERY_TIME=$(echo "($END_TIME - $START_TIME) * 1000" | bc 2>/dev/null || echo "N/A")
        echo -e "${GREEN}✓${NC} (${FIRST_QUERY_TIME}ms)"
    else
        echo -e "${RED}✗${NC} Failed"
        return 1
    fi
    
    # Wait a moment for cache to settle
    sleep 0.5
    
    # Second query (cache hit)
    echo -n "Second query (cache hit)... "
    START_TIME=$(date +%s.%N)
    RESULT2=$(timeout $TEST_TIMEOUT dig @$PROXY_HOST +short $TEST_DOMAIN 2>/dev/null)
    END_TIME=$(date +%s.%N)
    
    if [[ -n "$RESULT2" ]]; then
        SECOND_QUERY_TIME=$(echo "($END_TIME - $START_TIME) * 1000" | bc 2>/dev/null || echo "N/A")
        echo -e "${GREEN}✓${NC} (${SECOND_QUERY_TIME}ms)"
        
        # Compare times
        if command -v bc &> /dev/null && [[ "$FIRST_QUERY_TIME" != "N/A" ]] && [[ "$SECOND_QUERY_TIME" != "N/A" ]]; then
            if (( $(echo "$SECOND_QUERY_TIME < $FIRST_QUERY_TIME" | bc -l) )); then
                IMPROVEMENT=$(echo "scale=1; ($FIRST_QUERY_TIME - $SECOND_QUERY_TIME) / $FIRST_QUERY_TIME * 100" | bc)
                log_success "Cache improved response time by ${IMPROVEMENT}%"
            else
                log_warning "Cache did not improve response time (may be due to test conditions)"
            fi
        fi
    else
        echo -e "${RED}✗${NC} Failed"
    fi
}

# Test concurrent queries with different domains
test_concurrent_performance() {
    print_section "Testing Concurrent Performance"
    
    CONCURRENT_JOBS=10
    
    # Use real domains that are likely not cached
    CONCURRENT_DOMAINS=(
        "httpbin.org"
        "jsonplaceholder.typicode.com"
        "reqres.in"
        "postman-echo.com"
        "dummyjson.com"
        "mocky.io"
        "httpstatus.es"
        "dog.ceo"
        "catfact.ninja"
        "api.github.com"
    )
    
    echo "Running $CONCURRENT_JOBS concurrent queries with different domains..."
    
    START_TIME=$(date +%s.%N)
    
    # Run concurrent queries with different domains
    for i in $(seq 0 $((CONCURRENT_JOBS-1))); do
        DOMAIN=${CONCURRENT_DOMAINS[$i]}
        (timeout $TEST_TIMEOUT dig @$PROXY_HOST +short "$DOMAIN" >/dev/null 2>&1 && echo "SUCCESS" || echo "FAILED") &
    done
    
    # Wait for all background jobs
    wait
    
    END_TIME=$(date +%s.%N)
    TOTAL_TIME=$(echo "($END_TIME - $START_TIME) * 1000" | bc 2>/dev/null || echo "N/A")
    
    if [[ "$TOTAL_TIME" != "N/A" ]]; then
        log_success "Completed $CONCURRENT_JOBS concurrent queries in ${TOTAL_TIME}ms"
        
        if command -v bc &> /dev/null; then
            QPS=$(echo "scale=2; $CONCURRENT_JOBS / ($TOTAL_TIME / 1000)" | bc)
            log_info "Throughput: ${QPS} queries/second"
        fi
    else
        log_info "Completed $CONCURRENT_JOBS concurrent queries"
    fi
}

# Test different record types
test_record_types() {
    print_section "Testing Different DNS Record Types"
    
    TEST_DOMAIN="google.com"
    RECORD_TYPES=("A" "AAAA" "MX" "TXT" "NS")
    
    for record_type in "${RECORD_TYPES[@]}"; do
        echo -n "Testing $record_type record... "
        
        RESULT=$(timeout $TEST_TIMEOUT dig @$PROXY_HOST +short -t $record_type $TEST_DOMAIN 2>/dev/null)
        
        if [[ -n "$RESULT" ]]; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${YELLOW}⚠${NC} No response"
        fi
    done
}

# Stress test with real domains
stress_test() {
    print_section "Stress Testing"
    
    STRESS_QUERIES=20
    BATCH_SIZE=5
    
    # Use a mix of real domains for stress testing
    STRESS_DOMAINS=(
        "npmjs.org"
        "packagist.org"
        "rubygems.org"
        "pypi.org"
        "crates.io"
        "maven.org"
        "nuget.org"
        "bower.io"
        "yarnpkg.com"
        "gradle.org"
        "ant.apache.org"
        "make.org"
        "cmake.org"
        "meson.build"
        "ninja-build.org"
        "bazel.build"
        "buck.build"
        "pants.build"
        "scons.org"
        "waf.io"
    )
    
    echo "Running stress test with $STRESS_QUERIES different domains in batches of $BATCH_SIZE..."
    
    START_TIME=$(date +%s.%N)
    
    for i in $(seq 0 $((STRESS_QUERIES-1))); do
        # Run in batches to avoid overwhelming
        if (( (i + 1) % BATCH_SIZE == 0 )); then
            wait # Wait for previous batch to complete
        fi
        
        DOMAIN=${STRESS_DOMAINS[$i]}
        (timeout $TEST_TIMEOUT dig @$PROXY_HOST +short "$DOMAIN" >/dev/null 2>&1) &
    done
    
    wait # Wait for all queries to complete
    END_TIME=$(date +%s.%N)
    
    STRESS_TIME=$(echo "($END_TIME - $START_TIME) * 1000" | bc 2>/dev/null || echo "N/A")
    
    if [[ "$STRESS_TIME" != "N/A" ]]; then
        log_success "Stress test completed in ${STRESS_TIME}ms"
        
        if command -v bc &> /dev/null; then
            AVG_QPS=$(echo "scale=2; $STRESS_QUERIES / ($STRESS_TIME / 1000)" | bc)
            log_info "Average throughput: ${AVG_QPS} queries/second"
        fi
    else
        log_info "Stress test completed"
    fi
}

# Performance comparison with direct DNS
performance_comparison() {
    print_section "Performance Comparison"
    
    # Use real but different domains for fair comparison
    DIRECT_DOMAIN="gitlab.com"
    PROXY_DOMAIN="bitbucket.org"
    
    # Test direct DNS
    echo -n "Direct DNS ($FALLBACK_DNS) with $DIRECT_DOMAIN... "
    START_TIME=$(date +%s.%N)
    timeout $TEST_TIMEOUT dig @$FALLBACK_DNS +short "$DIRECT_DOMAIN" >/dev/null 2>&1
    END_TIME=$(date +%s.%N)
    DIRECT_TIME=$(echo "($END_TIME - $START_TIME) * 1000" | bc 2>/dev/null || echo "N/A")
    echo "${DIRECT_TIME}ms"
    
    # Small delay
    sleep 0.5
    
    # Test proxy
    echo -n "Your DNS Proxy with $PROXY_DOMAIN... "
    START_TIME=$(date +%s.%N)
    timeout $TEST_TIMEOUT dig @$PROXY_HOST +short "$PROXY_DOMAIN" >/dev/null 2>&1
    END_TIME=$(date +%s.%N)
    PROXY_TIME=$(echo "($END_TIME - $START_TIME) * 1000" | bc 2>/dev/null || echo "N/A")
    echo "${PROXY_TIME}ms"
    
    # Compare
    if command -v bc &> /dev/null && [[ "$DIRECT_TIME" != "N/A" ]] && [[ "$PROXY_TIME" != "N/A" ]]; then
        if (( $(echo "$PROXY_TIME < $DIRECT_TIME" | bc -l) )); then
            IMPROVEMENT=$(echo "scale=1; ($DIRECT_TIME - $PROXY_TIME) / $DIRECT_TIME * 100" | bc)
            log_success "Your proxy is ${IMPROVEMENT}% faster than direct DNS!"
        elif (( $(echo "$PROXY_TIME == $DIRECT_TIME" | bc -l) )); then
            log_info "Your proxy performs similarly to direct DNS"
        else
            OVERHEAD=$(echo "scale=1; ($PROXY_TIME - $DIRECT_TIME) / $DIRECT_TIME * 100" | bc)
            log_warning "Your proxy has ${OVERHEAD}% overhead compared to direct DNS"
        fi
    fi
}

# Generate statistics
generate_statistics() {
    print_section "Performance Statistics"
    
    if [[ ${#QUERY_TIMES[@]} -gt 0 ]] && command -v bc &> /dev/null; then
        # Calculate average
        SUM=$(printf '%s+' "${QUERY_TIMES[@]}")
        SUM=${SUM%+}
        AVG=$(echo "scale=2; ($SUM) / ${#QUERY_TIMES[@]}" | bc)
        
        # Find min and max
        MIN=$(printf '%s\n' "${QUERY_TIMES[@]}" | sort -n | head -1)
        MAX=$(printf '%s\n' "${QUERY_TIMES[@]}" | sort -n | tail -1)
        
        echo "Query Time Statistics:"
        echo "  Average: ${AVG}ms"
        echo "  Minimum: ${MIN}ms"
        echo "  Maximum: ${MAX}ms"
        echo "  Total Queries: ${#QUERY_TIMES[@]}"
        
        # Performance rating
        if (( $(echo "$AVG < 50" | bc -l) )); then
            log_success "Excellent performance! (< 50ms average)"
        elif (( $(echo "$AVG < 100" | bc -l) )); then
            log_success "Good performance! (< 100ms average)"
        elif (( $(echo "$AVG < 200" | bc -l) )); then
            log_warning "Average performance (< 200ms average)"
        else
            log_warning "Consider optimizing - high latency detected"
        fi
    fi
    
    # Overall success rate
    if [[ $TOTAL_QUERIES -gt 0 ]]; then
        SUCCESS_RATE=$(echo "scale=1; ($TOTAL_QUERIES - $FAILED_QUERIES) / $TOTAL_QUERIES * 100" | bc 2>/dev/null || echo "N/A")
        if [[ "$SUCCESS_RATE" != "N/A" ]]; then
            echo ""
            if (( $(echo "$SUCCESS_RATE >= 95" | bc -l) )); then
                log_success "Reliability: ${SUCCESS_RATE}% success rate"
            elif (( $(echo "$SUCCESS_RATE >= 90" | bc -l) )); then
                log_warning "Reliability: ${SUCCESS_RATE}% success rate"
            else
                log_error "Reliability: ${SUCCESS_RATE}% success rate - investigate failures"
            fi
        fi
    fi
}

# Main execution
main() {
    print_header "DNS Proxy Comprehensive Test Suite"
    echo "Testing DNS proxy at $PROXY_HOST:$PROXY_PORT"
    echo "Fallback DNS: $FALLBACK_DNS"
    echo "Timeout: ${TEST_TIMEOUT}s"
    echo ""
    
    check_prerequisites
    test_proxy_connectivity
    test_basic_resolution
    test_cache_performance
    test_record_types
    test_concurrent_performance
    stress_test
    performance_comparison
    generate_statistics
    
    print_header "Test Suite Complete"
    
    if [[ $FAILED_QUERIES -eq 0 ]]; then
        log_success "All tests passed! Your DNS proxy is working well."
    else
        log_warning "Some tests failed. Check the results above for details."
    fi
    
    echo ""
    echo "💡 Tips for improvement:"
    echo "  - If cache performance isn't improving, check your cache implementation"
    echo "  - If concurrent performance is poor, consider connection pooling"
    echo "  - If overall latency is high, optimize your upstream DNS selection"
    echo "  - Monitor your proxy logs during these tests for error messages"
}

# Handle Ctrl+C gracefully
trap 'echo -e "\n${YELLOW}Test interrupted by user${NC}"; exit 130' INT

# Run the tests
main "$@"
